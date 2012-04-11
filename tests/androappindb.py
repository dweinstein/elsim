#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

import sys
sys.path.append("./")

PATH_INSTALL = "../androguard"

sys.path.append(PATH_INSTALL)

from optparse import OptionParser

from elsim.similarity.similarity import *

from androguard.core import androconf
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis


DEFAULT_SIGNATURE = analysis.SIGNATURE_SEQUENCE_BB
option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_1 = { 'name' : ('-b', '--database'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_2 = { 'name' : ('-l', '--listdatabase'), 'help' : 'file : use these filenames', 'action' : 'count' }
option_3 = { 'name' : ('-d', '--display'), 'help' : 'display the file in human readable format', 'action' : 'count' }
option_4 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4]

def show_res(ret) :
    for i in ret :
        for j in ret[i] :
            for k in ret[i][j] :
                val = ret[i][j][k]
                if len(val[0]) == 1 and val[1] > 1:
                    continue

                if options.display :
                    print "\t", i, j, k, len(val[0]), val[1]
                else :
                    if val[2] == True :
                        print "\t", i, j, k, len(val[0]), val[1]

def eval_res(ret) :
    sorted_elems = {}
    for i in ret :
        sorted_elems[i] = []
        for j in ret[i] :
            final_value = 0
            total_value = 0
            elems = set()
#            print i, j, final_value
            for k in ret[i][j] :
                val = ret[i][j][k]
                total_value += 1 

                if len(val[0]) == 1 and val[1] > 1:
                    continue

                ratio = (len(val[0]) / float(val[1]))
#                print "\t", k, len(val[0]), val[1]
                if ratio > 0.2 :
                    if len(val[0]) > 10 or ratio > 0.8 :
                        final_value += ratio
                        elems.add( (k, ratio, len(val[0])) )

            if final_value != 0 : 
                #print "---->", i, j, (final_value/total_value)*100#, elems
                sorted_elems[i].append( (j, (final_value/total_value)*100, elems) )
        
        if len(sorted_elems[i]) == 0 :
            del sorted_elems[i]

    for i in sorted_elems :
        print i
        v = sorted(sorted_elems[i], key=lambda x: x[1])
        v.reverse()
        for j in v :
            print "\t", j[0], j[1]

############################################################
def main(options, arguments) :
    if options.input != None and options.database != None :
        ret_type = androconf.is_android( options.input )
        if ret_type == "APK" :
            a = apk.APK( options.input )
            d1 = dvm.DalvikVMFormat( a.get_dex() )
        elif ret_type == "DEX" :
            d1 = dvm.DalvikVMFormat( open(options.input, "rb").read() )
        
        dx1 = analysis.VMAnalysis( d1 )

        print "Finished parsing ...", len(d1.get_methods())
        sys.stdout.flush()

        n = SIMILARITY( "elsim/similarity/libsimilarity/libsimilarity.so" )
        n.set_compress_type( ZLIB_COMPRESS )


        db = DBFormat( options.database )

        elems_hash = set()
        for _class in d1.get_classes() :
        #    print _class.get_name()
            for method in _class.get_methods() :

                code = method.get_code()
                if code == None :
                    continue

                buff_list = dx1.get_method_signature( method, predef_sign = DEFAULT_SIGNATURE ).get_list()

                for i in buff_list :
                    elem_hash = long(n.simhash( i ))
                    elems_hash.add( elem_hash )

            #buff = dx1.get_method_signature(method, predef_sign = DEFAULT_SIGNATURE).get_string()
            #db.add_element( options.name, options.subname, long(n.simhash(buff)) )

        ret = db.elems_are_presents( elems_hash )
        #show_res(ret)
        eval_res(ret)


    elif options.database != None and options.listdatabase != None :
        db = DBFormat( options.database )
        db.show()

    elif options.version != None :
        print "Androappindb version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
