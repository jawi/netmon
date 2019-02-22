/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef MNL_EXTRA_H_
#define MNL_EXTRA_H_

#include <libmnl/libmnl.h>

#define VERIFY_attr(attr_type) \
	do { \
		if (mnl_attr_validate(attr, (attr_type)) < 0) { perror("mnl_attr_validate"); return MNL_CB_ERROR; } \
	} while (0)


#endif /* MNL_EXTRA_H_ */
