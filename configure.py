#!/usr/bin/env python
#
# Copyright 2001 Google Inc. All Rights Reserved.
#
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

"""Script that generates the build.ninja for ninja itself.

Projects that use ninja themselves should either write a similar script
or use a meta-build system that supports Ninja output."""

from optparse import OptionParser
import os
import sys
sys.path.insert(0, 'misc')

import ninja_syntax

parser = OptionParser()
platforms = ['linux', 'freebsd', 'mingw']
profilers = ['gmon', 'pprof']
parser.add_option('--platform',
                  help='target platform (' + '/'.join(platforms) + ')',
                  choices=platforms)
parser.add_option('--debug', action='store_true',
                  help='enable debugging flags',)
parser.add_option('--profile', metavar='TYPE',
                  choices=profilers,
                  help='enable profiling (' + '/'.join(profilers) + ')',)
parser.add_option('--with-gtest', metavar='PATH',
                  help='use gtest built in directory PATH')
(options, args) = parser.parse_args()

platform = options.platform
if platform is None:
    platform = sys.platform
    if platform.startswith('linux'):
        platform = 'linux'
    elif platform.startswith('freebsd'):
        platform = 'freebsd'
    elif platform.startswith('mingw') or platform.startswith('win'):
        platform = 'mingw'

BUILD_FILENAME = 'build.ninja'
buildfile = open(BUILD_FILENAME, 'w')
n = ninja_syntax.Writer(buildfile)
n.comment('This file is used to build ninja itself.')
n.comment('It is generated by ' + os.path.basename(__file__) + '.')
n.newline()

n.comment('The arguments passed to configure.py, for rerunning it.')
n.variable('configure_args', ' '.join(sys.argv[1:]))
n.newline()

def src(filename):
    return os.path.join('src', filename)
def built(filename):
    return os.path.join('$builddir', filename)
def doc(filename):
    return os.path.join('doc', filename)
def cxx(name, **kwargs):
    return n.build(built(name + '.o'), 'cxx', src(name + '.cc'), **kwargs)

n.variable('builddir', 'build')
n.variable('cxx', os.environ.get('CXX', 'g++'))
n.variable('ar', os.environ.get('AR', 'ar'))

cflags = ['-g', '-Wall', '-Wextra',
          '-Wno-deprecated',
          '-Wno-unused-parameter',
          '-fno-exceptions',
          '-fvisibility=hidden', '-pipe']
if not options.debug:
    cflags += ['-O2', '-DNDEBUG']
ldflags = ['-L$builddir']
libs = []

if platform == 'mingw':
    cflags.remove('-fvisibility=hidden');
    cflags.append('-Igtest-1.6.0/include')
    ldflags.append('-Lgtest-1.6.0/lib/.libs')
    ldflags.extend(['-static'])
else:
    if options.profile == 'gmon':
        cflags.append('-pg')
        ldflags.append('-pg')
    elif options.profile == 'pprof':
        libs.append('-lprofiler')

if 'CFLAGS' in os.environ:
    cflags.append(os.environ['CFLAGS'])
n.variable('cflags', ' '.join(cflags))
if 'LDFLAGS' in os.environ:
    ldflags.append(os.environ['LDFLAGS'])
n.variable('ldflags', ' '.join(ldflags))
n.newline()

n.rule('cxx',
       command='$cxx -MMD -MF $out.d $cflags -c $in -o $out',
       depfile='$out.d',
       description='CXX $out')
n.newline()

if platform != 'mingw':
    n.rule('ar',
           command='rm -f $out && $ar crs $out $in',
           description='AR $out')
else:
    n.rule('ar',
           command='cmd /c $ar cqs $out.tmp $in && move /Y $out.tmp $out',
           description='AR $out')
n.newline()

n.rule('link',
       command='$cxx $ldflags -o $out $in $libs',
       description='LINK $out')
n.newline()

objs = []

if platform != 'mingw':
    n.comment('browse_py.h is used to inline browse.py.')
    n.rule('inline',
           command='src/inline.sh $varname < $in > $out',
           description='INLINE $out')
    n.build(built('browse_py.h'), 'inline', src('browse.py'),
            implicit='src/inline.sh',
            variables=[('varname', 'kBrowsePy')])
    n.newline()

    objs += cxx('browse', order_only=built('browse_py.h'))
    n.newline()

n.comment('Core source files all build into ninja library.')
for name in ['build', 'build_log', 'clean', 'edit_distance', 'eval_env',
             'graph', 'graphviz', 'parsers', 'util', 'stat_cache',
             'disk_interface', 'state']:
    objs += cxx(name)
if platform == 'mingw':
    objs += cxx('subprocess-win32')
else:
    objs += cxx('subprocess')
ninja_lib = n.build(built('libninja.a'), 'ar', objs)
n.newline()

libs.append('-lninja')

n.comment('Main executable is library plus main() function.')
objs = cxx('ninja')
binary = 'ninja'
if platform == 'mingw':
    binary = 'ninja.exe'
n.build(binary, 'link', objs, implicit=ninja_lib,
        variables=[('libs', libs)])
n.newline()

n.comment('Tests all build into ninja_test executable.')

variables = []
test_cflags = None
test_ldflags = None
if options.with_gtest:
    path = options.with_gtest
    test_cflags = cflags + ['-I%s' % os.path.join(path, 'include')]
    test_libs = libs + [os.path.join(path, 'lib/.libs/lib%s.a' % lib)
                        for lib in ['gtest_main', 'gtest']]
else:
    test_libs = libs + ['-lgtest_main', '-lgtest']

objs = []
for name in ['build_log_test',
             'build_test',
             'clean_test',
             'disk_interface_test',
             'edit_distance_test',
             'eval_env_test',
             'graph_test',
             'graphviz_test',
             'parsers_test',
             'state_test',
             'subprocess_test',
             'test',
             'util_test']:
    objs += cxx(name, variables=[('cflags', test_cflags)])

if platform != 'mingw':
    test_libs.append('-lpthread')
n.build('ninja_test', 'link', objs, implicit=ninja_lib,
        variables=[('ldflags', test_ldflags),
                   ('libs', test_libs)])
n.newline()

n.comment('Perftest executable.')
objs = cxx('parser_perftest')
n.build('parser_perftest', 'link', objs, implicit=ninja_lib,
        variables=[('libs', '-L$builddir -lninja')])
n.newline()

n.comment('Generate a graph using the "graph" tool.')
n.rule('gendot',
       command='./ninja -t graph > $out')
n.rule('gengraph',
       command='dot -Tpng $in > $out')
dot = n.build(built('graph.dot'), 'gendot', ['ninja', 'build.ninja'])
n.build('graph.png', 'gengraph', dot)
n.newline()

n.comment('Generate the manual using asciidoc.')
n.rule('asciidoc',
       command='asciidoc -a toc -o $out $in',
       description='ASCIIDOC $in')
manual = n.build(doc('manual.html'), 'asciidoc', doc('manual.asciidoc'))
n.build('manual', 'phony',
        order_only=manual)
n.newline()

n.comment('Generate Doxygen.')
n.rule('doxygen',
       command='doxygen $in',
       description='DOXYGEN $in')
n.variable('doxygen_mainpage_generator',
           src('gen_doxygen_mainpage.sh'))
n.rule('doxygen_mainpage',
       command='$doxygen_mainpage_generator $in > $out',
       description='DOXYGEN_MAINPAGE $out')
mainpage = n.build(built('doxygen_mainpage'), 'doxygen_mainpage',
                   ['README', 'HACKING', 'COPYING'],
                   implicit=['$doxygen_mainpage_generator'])
n.build('doxygen', 'doxygen', doc('doxygen.config'),
        implicit=mainpage)
n.newline()

if platform != 'mingw':
    n.comment('Regenerate build files if build script changes.')
    n.rule('configure',
           command='./configure.py $configure_args',
           generator=True)
    n.build('build.ninja', 'configure',
            implicit=['configure.py', 'misc/ninja_syntax.py'])
    n.newline()

n.comment('Build only the main binary by default.')
n.default(binary)

print 'wrote %s.' % BUILD_FILENAME
