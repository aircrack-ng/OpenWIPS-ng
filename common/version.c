/*
 * OpenWIPS-ng - common stuff.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "version.h"


/* Return the version number */
char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc)
{
	int len;
	char * temp;
	char * provis = calloc(1,20);
	len = strlen(progname) + 200;
	temp = (char *) calloc(1,len);

	snprintf(temp, len, "%s %d.%d", progname, maj, min);

	if (submin > 0) {
		snprintf(provis, 20,".%d",submin);
		strncat(temp, provis, len - strlen(temp));
		memset(provis,0,20);
	}

	if (rc > 0) {
		snprintf(provis, 20, " rc%d", rc);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	} else if (beta > 0) {
		snprintf(provis, 20, " beta%d", beta);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	}

	if (svnrev > 0) {
		snprintf(provis, 20," r%d",svnrev);
		strncat(temp, provis, len - strlen(temp));
		memset(provis, 0, 20);
	}

	free(provis);
	temp = realloc(temp, strlen(temp)+1);
	return temp;
}
