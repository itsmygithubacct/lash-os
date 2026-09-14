/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2026 Mingyuan Li <2560359315@qq.com>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, version 2.1 of the License.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#ifndef LIBSSH_GETOPT_H
#define LIBSSH_GETOPT_H

#include "config.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
/* Bundled getopt fallback (src/external/getopt.c) */
extern int opterr, optind, optopt, optreset;
extern char *optarg;
int getopt(int nargc, char *const nargv[], const char *ostr);
#endif

#endif /* LIBSSH_GETOPT_H */
