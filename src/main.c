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
#include <poll.h>
#include <pwd.h>
#include <unistd.h>

#include "config.h"
#include "logging.h"
#include "mqtt.h"
#include "netlink.h"
#include "netmon.h"
#include "oui.h"
#include "util.h"

typedef struct event_queue_item {
    struct event_queue_item *next;
    event_t *event;
} event_queue_item_t;

enum events {
    EVENT_TERM = 1,
    EVENT_DUMP = 2,
    EVENT_RELOAD_CONFIG = 3,
    EVENT_RELOAD_OUI = 4,
};

enum fds {
    FD_EVENTS = 0,
    FD_NETLINK = 1,
    FD_MQTT = 2,
    _FD_MAX,
};

typedef struct state {
    bool loop;
    config_t *config;
    netlink_handle_t *nl_handle;
    mqtt_handle_t *mqtt_handle;

    int event_write_fd;

    event_queue_item_t *event_queue;

    struct pollfd fds[_FD_MAX];
} run_state_t;

static run_state_t run_state = { 0 };
oui_list_t *oui_list = { 0 };

/**
 * Netlink callback called for every Netlink event.
 */
static void netlink_event_callback(event_t *event) {
    event_queue_item_t *item = malloc(sizeof(event_queue_item_t));
    item->next = run_state.event_queue;
    item->event = event;
    run_state.event_queue = item;
}

static event_t *pop_event_queue(void) {
    event_queue_item_t *ptr = run_state.event_queue;
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
                run_state.event_queue = NULL;
            }
            free(ptr);
        }
    }

    return event;
}

static void flush_event_queue(void) {
    event_queue_item_t *ptr = run_state.event_queue;

    while (ptr) {
        event_queue_item_t *item = ptr;
        ptr = ptr->next;

        free_event(item->event);
        free(item);
    }
}

static void write_event(int fd, uint8_t event_type) {
    uint8_t buf[1] = { event_type };
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
        log_warning("Did not write all event data?!");
    }
}

static void signal_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        write_event(run_state.event_write_fd, EVENT_TERM);
    } else if (signo == SIGHUP) {
        write_event(run_state.event_write_fd, EVENT_RELOAD_CONFIG);
    } else if (signo == SIGUSR1) {
        write_event(run_state.event_write_fd, EVENT_DUMP);
    } else if (signo == SIGUSR2) {
        write_event(run_state.event_write_fd, EVENT_RELOAD_OUI);
    } else {
        log_debug("Unknown/unhandled signal: %d", signo);
    }
}

static void install_signal_handlers(void) {
    struct sigaction sigact;

    sigact.sa_handler = signal_handler;
    sigact.sa_flags = 0;

    sigemptyset(&sigact.sa_mask);

    sigaction(SIGUSR1, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGALRM, &sigact, NULL);
    sigaction(SIGCHLD, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);

    // Ignore SIGPIPE
    sigact.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sigact, NULL);
}

static void dump_config(config_t *config) {
    log_debug("Using configuration:");
    log_debug("- daemon user/group: %d/%d", config->priv_user, config->priv_group);
    if (config->vendor_lookup) {
        log_debug("- OUI vendor lookups from: %s", config->oui_file);
    }
    log_debug("- MQTT server: %s:%d", config->host, config->port);
    log_debug("  - client ID: %s", config->client_id);
    log_debug("  - MQTT QoS: %d", config->qos);
    log_debug("  - retain messages: %s", config->retain ? "yes" : "no");
    if (config->use_auth) {
        log_debug("  - using client credentials");
    }
    if (config->use_tls) {
        log_debug("- using TLS options:");
        log_debug("  - use TLS version: %s", config->tls_version);
        if (config->cacertpath) {
            log_debug("  - CA cert path: %s", config->cacertpath);
        }
        if (config->cacertfile) {
            log_debug("  - CA cert file: %s", config->cacertfile);
        }
        if (config->certfile) {
            log_debug("  - using client certificate: %s", config->certfile);
        }
        log_debug("  - verify peer: %s", config->verify_peer ? "yes" : "no");
        if (config->ciphers) {
            log_debug("  - cipher suite: %s", config->ciphers);
        }
    }
}

static void reload_oui_list(void) {
    oui_list_t *new_list = parse_oui_list(run_state.config->oui_file);
    oui_list_t *old_list = oui_list;

    oui_list = new_list;

    free_oui_list(old_list);
    log_info("OUI list reloaded.");
}

static void reload_config(const char *conf_file) {
    config_t *new_config = read_config(conf_file);
    config_t *old_config = run_state.config;

    // Sanity check; make sure we've got a valid configuration at hand...
    if (new_config == NULL) {
        run_state.loop = false;
    } else {
        // reconnect using the new configuration...
        disconnect_mqtt(run_state.mqtt_handle);

        run_state.config = new_config;

        free_config(old_config);

        dump_config(new_config);
        log_info("Configuration reloaded.");

        reload_oui_list();

        connect_mqtt(run_state.mqtt_handle, run_state.config);
    }
}

static void handle_netlink_data(int16_t revents) {
    if (revents & POLLIN) {
        log_debug("got netlink data to read...");

        if (netlink_read_data(run_state.nl_handle)) {
            log_warning("failed to read netlink data!");
        }
    } else if (revents & (POLLHUP | POLLERR)) {
        log_warning("netlink connection dropped!");

        disconnect_netlink(run_state.nl_handle);
        connect_netlink(run_state.nl_handle);
    }
}

static void handle_event_data(int16_t revents, int event_read_fd, const char *conf_file) {
    if (revents & POLLIN) {
        log_debug("got event data to read...");

        uint8_t buf[1] = { 0 };
        if (read(event_read_fd, &buf, sizeof(buf)) != sizeof(buf)) {
            log_warning("Did not read all event data?!");
            return;
        }

        switch (buf[0]) {
        case EVENT_TERM:
            run_state.loop = false;
            break;

        case EVENT_RELOAD_CONFIG:
            log_debug("Reloading configuration...");
            reload_config(conf_file);
            break;

        case EVENT_RELOAD_OUI:
            log_debug("Reloading OUI list...");
            reload_oui_list();
            break;

        case EVENT_DUMP:
            netlink_dump_data(run_state.nl_handle);
            break;

        default:
            log_debug("Unknown event received: %d", buf[0]);
            break;
        }
    } else if (revents & (POLLHUP | POLLERR)) {
        log_warning("Event connection dropped! Terminating...");
        run_state.loop = false;
    }
}

static void handle_mqtt_data(int16_t revents) {
    if (revents & POLLIN) {
        log_debug("got MQTT data to read...");

        if (mqtt_read_data(run_state.mqtt_handle)) {
            log_warning("unable to read MQTT data!");
        }
    } else if (revents & POLLOUT) {
        log_debug("got MQTT data to write...");

        if (mqtt_write_data(run_state.mqtt_handle)) {
            log_warning("unable to write MQTT data!");
        }
    } else if (revents & (POLLHUP | POLLERR)) {
        log_warning("MQTT connection dropped!");

        disconnect_mqtt(run_state.mqtt_handle);
        connect_mqtt(run_state.mqtt_handle, run_state.config);
    }
}

int main(int argc, char *argv[]) {
    const nfds_t nfds = _FD_MAX;

    int event_pipe[2] = { 0, 0 };

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

    // install the signal handling routine
    install_signal_handlers();

    run_state.config = read_config(conf_file);

    // Sanity check; make sure we've got a valid configuration at hand...
    if (run_state.config == NULL) {
        goto cleanup;
    }

    dump_config(run_state.config);

    oui_list = parse_oui_list(run_state.config->oui_file);

    if (!foreground) {
        int retval = daemonize(pid_file, run_state.config->priv_user, run_state.config->priv_group);
        if (retval) {
            exit(retval);
        }
    }

    // Netlink initialization...
    run_state.nl_handle = init_netlink(netlink_event_callback);
    if (!run_state.nl_handle) {
        log_warning("Netlink initialization failed!");
        return -1;
    }

    // MQTT initialization...
    run_state.mqtt_handle = init_mqtt();
    if (!run_state.mqtt_handle) {
        log_warning("MQTT initialization failed!");
        return -1;
    }

    // allow events to be sent through a pipe...
    if (pipe(event_pipe) < 0) {
        perror("pipe");
        return ERR_PIPE;
    }

    // Keep track of the writing side...
    run_state.event_write_fd = event_pipe[1];

    // Prepare the netlink connection...
    if (connect_netlink(run_state.nl_handle)) {
        log_warning("netlink connection failed!");
        return -1;
    }

    // Prepare the MQTT connection...
    if (connect_mqtt(run_state.mqtt_handle, run_state.config)) {
        log_warning("MQTT connection failed!");
        return -1;
    }

    run_state.loop = true;

    while (run_state.loop) {
        // Re-initialize the events we're interested in...
        run_state.fds[FD_EVENTS].fd = event_pipe[0];
        run_state.fds[FD_EVENTS].events = POLLIN;

        run_state.fds[FD_NETLINK].fd = netlink_fd(run_state.nl_handle);
        run_state.fds[FD_NETLINK].events = POLLIN;

        run_state.fds[FD_MQTT].fd = mqtt_fd(run_state.mqtt_handle);
        run_state.fds[FD_MQTT].events = POLLIN;
        if (mqtt_wants_to_write(run_state.mqtt_handle)) {
            run_state.fds[FD_MQTT].events |= POLLOUT;
        }

        int count = poll(run_state.fds, nfds, 100);
        if (count < 0) {
            if (errno == EINTR) {
                log_debug("poll was interrupted by system signal; ignoring...");
            } else {
                log_warning("failed to poll: %m");
                break;
            }
        } else if (count > 0) {
            // There was something of interest; let's look a little closer...
            if (run_state.fds[FD_NETLINK].revents) {
                handle_netlink_data(run_state.fds[FD_NETLINK].revents);
            } else if (run_state.fds[FD_EVENTS].revents) {
                handle_event_data(run_state.fds[FD_EVENTS].revents, event_pipe[0], conf_file);
            } else if (run_state.fds[FD_MQTT].revents) {
                handle_mqtt_data(run_state.fds[FD_MQTT].revents);
            }
        }

        // Update MQTTs internal administration...
        mqtt_update_administration(run_state.mqtt_handle);

        event_t *event = pop_event_queue();
        if (event != NULL) {
            publish_mqtt(run_state.mqtt_handle, event);

            // Clean up the resources...
            free_event(event);
        }
    }

    log_info(PNAME " terminating.");

cleanup:
    disconnect_netlink(run_state.nl_handle);
    disconnect_mqtt(run_state.mqtt_handle);

    flush_event_queue();

    // Close our local resources...
    close(event_pipe[0]);
    close(event_pipe[1]);

    destroy_netlink(run_state.nl_handle);
    destroy_mqtt(run_state.mqtt_handle);
    destroy_logging();

    free_oui_list(oui_list);

    free_config(run_state.config);

    // best effort; will only succeed if the permissions are set correctly...
    unlink(pid_file);

    free(conf_file);
    free(pid_file);

    return 0;
}
