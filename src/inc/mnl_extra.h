/*
 * mnl_extra.h
 *
 *  Created on: Jan 18, 2019
 *      Author: jawi
 */

#ifndef MNL_EXTRA_H_
#define MNL_EXTRA_H_

#include <libmnl/libmnl.h>

#define VERIFY_attr(attr_type) \
	do { \
		if (mnl_attr_validate(attr, (attr_type)) < 0) { perror("mnl_attr_validate"); return MNL_CB_ERROR; } \
	} while (0)


#endif /* MNL_EXTRA_H_ */
