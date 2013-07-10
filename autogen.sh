#! /bin/sh
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# 2011-
#    Oscar Koeroo <okoeroo@gmail.nl>
#

set -x

# On MacOS X, the GNU libtool is named `glibtool'.
HOSTOS=`uname`
LIBTOOLIZE=libtoolize
if test "$HOSTOS"x = Darwinx; then
    LIBTOOLIZE=glibtoolize
fi


#if test ! -d "autodir" ; then
#    mkdir autodir
#fi

aclocal -I m4 && \
$LIBTOOLIZE --force --copy && \
autoheader && \
automake --add-missing --copy && \
autoconf || echo "Something went wrong! Check the above output."

