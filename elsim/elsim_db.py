#!/usr/bin/env python

# This file is part of Elsim.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Elsim is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Elsim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Elsim.  If not, see <http://www.gnu.org/licenses/>.


import logging

from similarity.similarity_db import *

from androguard.core.analysis import analysis

DEFAULT_SIGNATURE = analysis.SIGNATURE_SEQUENCE_BB

def show_res(ret) :
    for i in ret :
        for j in ret[i] :
            for k in ret[i][j] :
                val = ret[i][j][k]
                if len(val[0]) == 1 and val[1] > 1:
                    continue

                print "\t", i, j, k, len(val[0]), val[1]

def eval_res_per_class(ret) :
    z = {}

    for i in ret :
        for j in ret[i] :
            for k in ret[i][j] :
                val = ret[i][j][k]
                if len(val[0]) == 1 and val[1] > 1 :
                    continue
               
                if len(val[0]) == 0:
                    continue

                if j not in z :
                    z[j] = {}
                
                val_percentage = (len(val[0]) / float(val[1]) ) * 100
                if (val_percentage != 0) :
                    z[j][k] = val_percentage
                    
    return z

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
                #print "\t", k, len(val[0]), val[1], ratio
                if ratio > 0.2 :
                    if len(val[0]) > 10 or ratio > 0.8 :
                        final_value += ratio
                        elems.add( (k, ratio, len(val[0])) )

            if final_value != 0 : 
                #print "---->", i, j, (final_value/total_value)*100#, elems
                sorted_elems[i].append( (j, (final_value/total_value)*100, elems) )

        if len(sorted_elems[i]) == 0 :
            del sorted_elems[i]

    return sorted_elems

def show_sorted_elems(sorted_elems):
    for i in sorted_elems :
        print i
        v = sorted(sorted_elems[i], key=lambda x: x[1])
        v.reverse()
        for j in v :
            print "\t", j[0], j[1]

############################################################

class ElsimDB :
    def __init__(self, vm, vmx, database_path) :
        self.vm = vm
        self.vmx = vmx
        self.db = DBFormat( database_path )

    def percentage(self) :
        elems_hash = set()
        for _class in self.vm.get_classes() :
            for method in _class.get_methods() :

                code = method.get_code()
                if code == None :
                    continue

                buff_list = self.vmx.get_method_signature( method, predef_sign = DEFAULT_SIGNATURE ).get_list()

                for i in buff_list :
                    elem_hash = long(simhash( i ))
                    elems_hash.add( elem_hash )

        ret = self.db.elems_are_presents( elems_hash )
        sorted_ret = eval_res(ret)

        info = []

        for i in sorted_ret :
            v = sorted(sorted_ret[i], key=lambda x: x[1])
            v.reverse()

            for j in v :
                info.append( [j[0], j[1]] )

        return info

    def show(self) :
        info = { "info" : [], "nodes" : [], "links" : []}
        N = {}
        L = {}

        for _class in self.vm.get_classes() :
            elems_hash = set()
        #    print _class.get_name()
            for method in _class.get_methods() :

                code = method.get_code()
                if code == None :
                    continue

                buff_list = self.vmx.get_method_signature( method, predef_sign = DEFAULT_SIGNATURE ).get_list()

                for i in buff_list :
                    elem_hash = long(simhash( i ))
                    elems_hash.add( elem_hash )

            #buff = dx1.get_method_signature(method, predef_sign = DEFAULT_SIGNATURE).get_string()
            #db.add_element( options.name, options.subname, long(n.simhash(buff)) )

            ret = self.db.elems_are_presents( elems_hash )
            sort_ret = eval_res_per_class( ret )
            if sort_ret != {} :
                if _class.get_name() not in N :
                    info["nodes"].append( { "name" : _class.get_name().split("/")[-1], "group" : 0 } ) 
                    N[_class.get_name()] = len(N)
            
                #print "!!!! ", _class.get_name()
                for j in sort_ret : 
                #    print j
                    
                    if j not in N : 
                        N[j] = len(N)
                        info["nodes"].append( { "name" : j, "group" : 1 } )

                    key = _class.get_name() + j
                    if key not in L :
                #        print key
                        L[ key ] = { "source" : N[_class.get_name()], "target" : N[j], "value" : 0 } 
                        info["links"].append( L[ key ] )

                    for k in sort_ret[j] :
                #        print sort_ret[j][k]
                        if sort_ret[j][k] > L[ key ]["value"] :
                            L[ key ]["value"] = sort_ret[j][k]

        return info

            #show_res(ret)
            #sorted_ret = eval_res(ret)
            #show_sorted_elems(sorted_ret)
