# This file is part of Elsim
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


import json
class DBFormat:
    def __init__(self, filename):
        self.filename = filename
       
        self.D = {}

        try :
            fd = open(self.filename, "r")
            self.D = json.load( fd )
            fd.close()
        except IOError :
            import logging
            logging.info("OOOOOPS")
            pass

        self.H = {}
        for i in self.D :
            self.H[i] = {}
            for j in self.D[i] :
                self.H[i][j] = {}
                for k in self.D[i][j] :
                    self.H[i][j][k] = set()
                    for e in self.D[i][j][k] :
                        self.H[i][j][k].add( e )

    def add_element(self, name, sname, sclass, elem):
        try :
            if elem not in self.D[ name ][ sname ][ sclass ] :
                self.D[ name ][ sname ][ sclass ].append( elem )
        except KeyError :
            if name not in self.D :
                self.D[ name ] = {}
                self.D[ name ][ sname ] = {}
                self.D[ name ][ sname ][ sclass ] = []
                self.D[ name ][ sname ][ sclass ].append( elem )
            elif sname not in self.D[ name ] :
                self.D[ name ][ sname ] = {}
                self.D[ name ][ sname ][ sclass ] = []
                self.D[ name ][ sname ][ sclass ].append( elem )
            elif sclass not in self.D[ name ][ sname ] :
                self.D[ name ][ sname ][ sclass ] = []
                self.D[ name ][ sname ][ sclass ].append( elem )

    def is_present(self, elem) :
        for i in self.D :
            if elem in self.D[i] :
                return True, i
        return False, None

    def elems_are_presents(self, elems) :
        ret = {}

        for i in self.H:
            ret[i] = {}
            for j in self.H[i] :
                ret[i][j] = {}
                for k in self.H[i][j] :
                    val = [self.H[i][j][k].intersection(elems), len(self.H[i][j][k])]

                    ret[i][j][k] = val
                    if ((float(len(val[0]))/(val[1])) * 100) >= 50 :
                    #if len(ret[j][0]) >= (ret[j][1] / 2.0) :
                        val.append(True)
                    else:
                        val.append(False)

        return ret

    def show(self) :
        for i in self.D :
            print i, ":"
            for j in self.D[i] :
                print "\t", j, len(self.D[i][j])
                for k in self.D[i][j] :
                    print "\t\t", k, len(self.D[i][j][k])

    def save(self):
        fd = open(self.filename, "w")
        json.dump(self.D, fd)
        fd.close()

def simhash(x) :
    import simhash
    return simhash.simhash(x)
