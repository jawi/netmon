/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>

#include "config.h"
#include "logging.h"
#include "nats.h"
#include "netlink.h"
#include "netmon.h"
#include "util.h"

#define ERR_UNKNOWN 1
#define ERR_PIPE 10
#define ERR_FORK 11
#define ERR_PIPE_READ 12
#define ERR_SETSID 20
#define ERR_DAEMONIZE 21
#define ERR_DEV_NULL 22
#define ERR_PID_FILE 23
#define ERR_CONFIG 24
#define ERR_CHDIR 25
#define ERR_DROP_PRIVS 26

typedef struct event_queue_item {
    struct event_queue_item *next;
    event_t *event;
} event_queue_item_t;

typedef struct state {
    bool loop;
    config_t *config;

    pthread_t tid[2];
    event_queue_item_t *event_queue;
    pthread_mutex_t mutex;
    pthread_cond_t events_present;
} run_state_t;

static run_state_t run_state;

#define PTHREAD_TERMINATE() \
	pthread_exit(0); \
	return NULL

static void flush_event_queue(void) {
    event_queue_item_t *ptr = run_state.event_queue;

    while (ptr) {
        event_queue_item_t *item = ptr;
        ptr = ptr->next;

        free_event(item->event);
        free(item);
    }
}

static void event_producer_callback(event_t *event) {
    pthread_mutex_lock(&(run_state.mutex));

    event_queue_item_t *item = malloc(sizeof(event_queue_item_t));
    item->next = run_state.event_queue;
    item->event = event;
    run_state.event_queue = item;

    pthread_cond_signal(&(run_state.events_present));

    pthread_mutex_unlock(&(run_state.mutex));

    // log_debug("publishing event = %s", event[0]->data);
}

static void event_producer_cleanup(void *arg) {
    netlink_handle_t *netlink_handle = (netlink_handle_t *)arg;

    log_debug("terminating producer thread...");

    disconnect_netlink(netlink_handle);
    destroy_netlink(netlink_handle);
}

static void *event_producer_thread(void *arg) {
    run_state_t *state = (run_state_t *) arg;

    netlink_handle_t *handle = init_netlink(event_producer_callback);
    if (!handle) {
        log_warning("netlink initialization failed!");
        PTHREAD_TERMINATE();
    }

    // Make sure we clean up the mess we've made...
    pthread_cleanup_push(event_producer_cleanup, handle);

    if (connect_netlink(handle)) {
        log_warning("netlink connection failed!");
        PTHREAD_TERMINATE();
    }

    log_debug("starting producer thread main loop...");

    while (state->loop) {
        netlink_loop(handle);
    }

    pthread_cleanup_pop(1 /* execute */);

    PTHREAD_TERMINATE();
}

static void event_consumer_cleanup(void *arg) {
    nats_handle_t *nats_handle = (nats_handle_t *)arg;

    log_debug("Terminating consumer thread...");

    disconnect_nats(nats_handle);
    destroy_nats(nats_handle);
}

static void *event_consumer_thread(void *arg) {
    run_state_t *state = (run_state_t *) arg;

    nats_handle_t *nats_handle = init_nats();
    if (!nats_handle) {
        log_warning("NATS initialization failed!");
        PTHREAD_TERMINATE();
    }

    // Make sure we clean up the mess we've made...
    pthread_cleanup_push(event_consumer_cleanup, nats_handle);

    if (connect_nats(nats_handle, state->config)) {
        log_error("Failed to connect to NATS, giving up...");
        PTHREAD_TERMINATE();
    }

    log_debug("Starting consumer thread main loop...");

    while (state->loop) {
        pthread_mutex_lock(&(state->mutex));

        while (!state->event_queue) {
            pthread_cond_wait(&(state->events_present), &(state->mutex));
        }

        event_queue_item_t *ptr = state->event_queue;
        event_t *event = NULL;

        if (ptr) {
            event_queue_item_t *prev = NULL;
            while (ptr->next) {
                prev = ptr;
                ptr = ptr->next;
            }

            if (ptr) {
                event = ptr->event;
                // consume event_queue_item item...
                if (prev) {
                    prev->next = NULL;
                } else {
                    state->event_queue = NULL;
                }
                free(ptr);
            }
        }

        pthread_mutex_unlock(&(state->mutex));

        if (event) {
            // log_debug("consumer received an event: %s!", event->data);

            publish_nats(nats_handle, event);

            free_event(event);
        }
    }

    pthread_cleanup_pop(1 /* execute */);

    PTHREAD_TERMINATE();
}

static int daemon_start(run_state_t *state) {
    state->loop = true;

    pthread_mutex_init(&(state->mutex), NULL);
    pthread_cond_init(&(state->events_present), NULL);

    int ret;

    ret = pthread_create(&(state->tid[0]), NULL, event_producer_thread, state);
    if (ret) {
        log_error("failed to create thread: %m");
        return -1;
    }

    ret = pthread_setname_np(state->tid[0], "mnl handler");
    if (ret) {
        // non-fatal
        log_warning("failed to set name for producer thread: %m");
    }

    ret = pthread_create(&(state->tid[1]), NULL, event_consumer_thread, state);
    if (ret) {
        log_error("failed to create thread: %m");
        return -1;
    }

    ret = pthread_setname_np(state->tid[1], "mqtt handler");
    if (ret) {
        // non-fatal
        log_warning("failed to set name for consumer thread: %m");
    }

    log_info(PNAME " v" VERSION " started.");

    pthread_join(state->tid[0], NULL);
    pthread_join(state->tid[1], NULL);

    flush_event_queue();

    return 0;
}

#define SAFE_SIGNAL(rc) \
    int _rc = rc; \
    if (write(err_pipe[1], &_rc, 1) != 1) { \
        log_warning("failed to write single byte to pipe!"); \
    } \
    close(err_pipe[1]);

#define SIGNAL_SUCCESS() \
	do { \
        SAFE_SIGNAL(0) \
	} while (0)

#define SIGNAL_FAILURE(rc) \
	do { \
        SAFE_SIGNAL(rc) \
		exit(rc); \
	} while (0)

static int daemonize(const char *pid_file, uid_t uid, gid_t gid) {
    // create a anonymous pipe to communicate between daemon and our parent...
    int err_pipe[2] = { 0 };
    if (pipe(err_pipe) < 0) {
        perror("pipe");
        return ERR_PIPE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return ERR_FORK;
    } else if (pid > 0) {
        // parent, wait until daemon is finished initializing...
        close(err_pipe[1]);

        int rc = 0;
        if (read(err_pipe[0], &rc, 1) < 0) {
            rc = ERR_PIPE_READ;
        }
        exit(rc);
    } else { /* pid == 0 */
        // first child continues here...
        // NOTE: we can/should communicate our state to our parent in order for it to terminate!

        // we only write to this pipe...
        close(err_pipe[0]);

        // create a new session...
        pid = setsid();
        if (pid < 0) {
            SIGNAL_FAILURE(ERR_SETSID);
        }

        // fork again to ensure the daemon cannot take back the controlling tty...
        pid = fork();
        if (pid < 0) {
            SIGNAL_FAILURE(ERR_DAEMONIZE);
        } else if (pid > 0) {
            // terminate first child...
            exit(0);
        } else { /* pid == 0 */
            // actual daemon starts here...
            int fd;

            if ((fd = open("/dev/null", O_RDWR)) < 0) {
                log_error("unable to open /dev/null: %s", strerror(errno));
                SIGNAL_FAILURE(ERR_DEV_NULL);
            } else {
                dup2(fd, STDIN_FILENO);
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }

            umask(0);

            if (chdir("/") != 0) {
                log_error("unable to change directory: %m");
                SIGNAL_FAILURE(ERR_CHDIR);
            }

            if (write_pidfile(pid_file, uid, gid)) {
                SIGNAL_FAILURE(ERR_PID_FILE);
            }

            if (drop_privileges(uid, gid)) {
                SIGNAL_FAILURE(ERR_DROP_PRIVS);
            }

            // Finish startup...
            if (err_pipe[1] != -1) {
                SIGNAL_SUCCESS();
            }
        } /* daemon pid == 0 */
    } /* first child pid == 0 */

    return 0;
}

static void signal_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        run_state.loop = false;

        pthread_cancel(run_state.tid[0]);
        pthread_cancel(run_state.tid[1]);
    }
}

int main(int argc, char *argv[]) {
    // parse arguments...
    char *conf_file = NULL;
    char *pid_file = NULL;

    bool foreground = false;
    bool debug = false;
    int opt;

    while ((opt = getopt(argc, argv, "c:dfhp:v")) != -1) {
        switch (opt) {
        case 'c':
            conf_file = strdup(optarg);
            break;
        case 'd':
            debug = true;
            break;
        case 'f':
            foreground = true;
            break;
        case 'p':
            pid_file = strdup(optarg);
            break;
        case 'v':
        case 'h':
        default:
            fprintf(stderr, PNAME " v" VERSION "\n");
            if (opt == 'v') {
                exit(0);
            }
            fprintf(stderr, "Usage: %s [-d] [-f] [-c config file] [-p pid file] [-v]\n", PNAME);
            exit(1);
        }
    }

    if (!conf_file) {
        conf_file = strdup(CONF_FILE);
    }
    if (!pid_file) {
        pid_file = strdup(PID_FILE);
    }

    // close any file descriptors we inherited...
    const long max_fd = sysconf(_SC_OPEN_MAX);
    for (int fd = 3; fd < max_fd; fd++) {
        close(fd);
    }
    // do this *after* we've closed the file descriptors!
    init_logging(debug, foreground);

    struct sigaction sigact;

    // install the signal handling routine
    sigact.sa_handler = signal_handler;
    sigact.sa_flags = 0;
    sigemptyset(&sigact.sa_mask);

    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);

    run_state.config = read_config(conf_file);

    if (run_state.config == NULL) {
        exit(EXIT_FAILURE);
    }

    log_debug("Using configuration:");
    if (!foreground) {
        log_debug("- daemon user/group: %d/%d", run_state.config->priv_user, run_state.config->priv_group);
    }
    log_debug("- NATS server: %s:%d", run_state.config->host, run_state.config->port);
    log_debug("  - client ID: %s", run_state.config->client_id);
    if (run_state.config->use_auth) {
        log_debug("  - using client credentials");
    }
    if (run_state.config->use_tls) {
        log_debug("- using TLS options:");
        log_debug("  - use TLS version: %s", run_state.config->tls_version);
        if (run_state.config->cacertfile) {
            log_debug("  - CA cert file: %s", run_state.config->cacertfile);
        }
        if (run_state.config->certfile) {
            log_debug("  - using client certificate: %s", run_state.config->certfile);
        }
        log_debug("  - verify peer: %s", run_state.config->verify_peer ? "yes" : "no");
        if (run_state.config->ciphers) {
            log_debug("  - cipher suite: %s", run_state.config->ciphers);
        }
    }

    if (!foreground) {
        int retval = daemonize(pid_file, run_state.config->priv_user, run_state.config->priv_group);
        if (retval) {
            exit(retval);
        }
    }

    daemon_start(&run_state);

    log_info(PNAME " terminating.");

    free_config(run_state.config);
    destroy_logging();

    // best effort; will only succeed if the permissions are set correctly...
    unlink(pid_file);

    free(conf_file);
    free(pid_file);

    return 0;
}
