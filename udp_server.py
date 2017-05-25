# udp_server - Test udp server stub.
# Copyright (C) 2016  Govind Singh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# govind.singh@stud.tu-darmstadt.de, Technical University Darmstadt

import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
server_address = ('192.168.56.1', 5006)
print 'starting udp server...'
sock.bind(server_address)

while True:
    print 'waiting to receive message'
    data, address = sock.recvfrom(4096)
    print 'data received :',data
	
    if data:
        sent = sock.sendto(data, address)
        print 'data replied!!!'
