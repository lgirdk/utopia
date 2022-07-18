##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2022 Liberty Global B.V
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS =

bin_PROGRAMS = dns_filter

dns_filter_SOURCES = dns_filter.c

dns_filter_CPPFLAGS = -I$(top_srcdir)/source/ulog \
                   -I$(top_srcdir)/source/include

dns_filter_LDFLAGS = -lnetfilter_queue -lnfnetlink -lresolv

dns_filter_LDADD = $(top_builddir)/source/ulog/libulog.la \
                $(top_builddir)/source/syscfg/lib/libsyscfg.la
