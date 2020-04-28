#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#	    
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#			    
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

APXS=apxs2
APXS_OPTS=-Wc, -Wc,-DDST_CLASS=3
SRC=mod_spamhaus.c
OBJ=.libs/mod_spamhaus.so

$(OBJ): $(SRC)
	@echo 
	$(APXS) $(APXS_OPTS) -c $(SRC)
	@echo
	@echo write '"make install"' to install module
	@echo

install: $(OBJ)
	$(APXS) $(APXS_OPTS) -i -a -n spamhaus mod_spamhaus.la

clean:
	rm -f .libs/*
	rm -f *.o
	rm -f *.lo
	rm -f *.la
	rm -f *.slo
	rmdir .libs
