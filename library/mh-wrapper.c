/*
 # This file is part of the Ops-T Portal.
 #
 #   Copyright 2014 Operations Security Administration, Inc.
 #
 #   Licensed under the Apache License, Version 2.0 (the "License");
 #   you may not use this file except in compliance with the License.
 #   You may obtain a copy of the License at
 #
 #       http://www.apache.org/licenses/LICENSE-2.0
 #
 #   Unless required by applicable law or agreed to in writing, software
 #   distributed under the License is distributed on an "AS IS" BASIS,
 #   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #   See the License for the specific language governing permissions and
 #   limitations under the License.
 #
 */

#ifdef linux
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

int
main(int argc, char *argv[], char *envp[]) {
	const char wrapped[] = STR(WRAPPED);
#ifdef linux
	uid_t new_gid;
	uid_t new_uid, ruid, euid, suid;

	new_gid = getegid();
	new_uid = geteuid();

	if (setresgid(new_gid, new_gid, new_gid) < 0) {
		perror("setresgid()");
		return (1);
	}

	if (setresuid(new_uid, new_uid, new_uid) < 0) {
		perror("setresuid()");
		return (1);
	}

	if (getresuid(&ruid, &euid, &suid) < 0) {
		perror("getresuid()");
		return (1);
	}
#else
	if (setgid(getegid()) != 0) {
		perror("setgid()");
		return (1);
	}

	if (setuid(geteuid()) != 0) {
		perror("setuid()");
		return (1);
	}
#endif

        execve(wrapped, argv, envp);

	/* Should not be reached */
	perror("execve()");

	return (1);
}

