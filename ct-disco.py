#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ct-disco v0.1 - ramon.pinuaga@skyscanner.net
# Certstream CTL monitor

import sys
import certstream
import time

cert_count=0
MAX=1000000
KEYWORD="sentry"

def on_open():
    sys.stdout.write("\n")

def on_error(instance, exception):
    sys.stdout.write("xxxException in CertStreamClient! -> {}\n".format(exception)) 

# Event processing
def process_stream(message, context):
    global cert_count

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        cert_count=cert_count+len(all_domains)

        for d in all_domains:
            # Actions per domain
            ####################
            sys.stdout.write(".")
            #sys.stdout.write(d + "\n")

            # Search by keyword
            if(d.count(KEYWORD)): sys.stdout.write("\n--> " + d + "\n")

        sys.stdout.flush()
        sys.stdout.write("\r")

        # Exit condition
        if(cert_count>MAX):
            sys.stdout.write("--EOF\n")
            end_time = time.time()
            elapsed_time = end_time - start_time
            sys.stdout.write("Time to parse " + str(MAX) + " domains: " + str(elapsed_time) + " seconds\n") 
            sys.exit()

# MAIN
start_time = time.time()
sys.stdout.write("++ Listening for events:\n")
certstream.listen_for_events(process_stream, on_open=on_open, on_error=on_error, url='wss://certstream.calidog.io/')