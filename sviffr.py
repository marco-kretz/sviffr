#!/usr/bin/env python3
#
# SVIFFR - Yet another network-sniffer
#
# @author: Marco 'zantekk' K. <zantekk@gmail.com>
#
# -*- coding: utf-8 -*-

import sys
import engine

if len(sys.argv) < 2 or len(sys.argv) > 2:
	sys.exit('Usage: %s <tcp|udp|both>' % sys.argv[0])
elif sys.argv[1] in ['tcp', 'udp']:
	sviffr = engine.Sviffr(sys.argv[1])
	sviffr.start()
elif sys.argv[1] == 'both':
	sviffr_udp = engine.Sviffr('udp')
	sviffr_tcp = engine.Sviffr('tcp')
	sviffr_udp.start()
	sviffr_tcp.start()
