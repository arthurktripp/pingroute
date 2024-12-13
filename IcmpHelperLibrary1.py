# #################################################################################################################### #
# Citation:                                                                                                            #
# Adapted from course materials and skeleton code from Oregon State University                                         #
#     CS 372 - Intro to Computer Networks                                                                              #
# All other code my own                                                                                                #
#                                                                                                                      #
# #################################################################################################################### #

from icmp_types import get_icmp_message
import keyboard
import os
from socket import *
import struct
import time
import select


class IcmpHelperLibrary:
    '''ICMP Packet subclasses and methods'''
    class IcmpPacket:
        '''ICMP Packet to send'''

        # subclass variables:
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpType = 0
        # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetChecksum = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0
        __ipTimeout = 20                # Original value: 30
        __ttl = 255                     # Time to live | Original value 255
        __request_type = "ping"         # ping or traceroute

        # set True for verbose debugging
        __DEBUG_IcmpPacket = False

        # getters:
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # setters
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(
                    self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def set_request_type(self, type):
            self.__request_type = type

        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {
                  "Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count +
                                           1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {
                      hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(
                    checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = (checksum >> 16) + \
                checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            # Used to track overall round trip time
            data_time = struct.pack("d", time.time())
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            # packHeader() and encodeData() transfer data to their respective bit
            self.__packHeader()
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.

            # Getting data from the response
            reply_icmp_identifier = icmpReplyPacket.getIcmpIdentifier()
            reply_icmp_sequence_number = icmpReplyPacket.getIcmpSequenceNumber()
            reply_icmp_data = icmpReplyPacket.getIcmpData()

            # Getting data from the sent packet
            og_icmp_identifier = self.getPacketIdentifier()
            og_icmp_sequence_number = self.getPacketSequenceNumber()
            og_icmp_data = self.getDataRaw()

            # set _isvalid values in reply
            if reply_icmp_identifier == og_icmp_identifier:
                icmpReplyPacket.set_icmp_identifier_isvalid(True)
            if reply_icmp_sequence_number == og_icmp_sequence_number:
                icmpReplyPacket.set_icmp_sequence_number_isvalid(True)
            if reply_icmp_data == og_icmp_data:
                icmpReplyPacket.set_icmp_data_isvalid(True)

            if all([icmpReplyPacket.get_icmp_identifier_isvalid(),
                    icmpReplyPacket.get_icmp_sequence_number_isvalid(),
                    icmpReplyPacket.get_icmp_data_isvalid()]):
                icmpReplyPacket.setIsValidResponse(True)
            else:
                print(f'ERROR: ICMP Reply has unexpected values:\n',
                      f'Expected Identifier: {og_icmp_identifier}  |  Reply Identifier: {
                          reply_icmp_identifier}\n',
                      f'Expected Sequence Number: {og_icmp_sequence_number}  |  Reply Sequence Number: {
                          reply_icmp_sequence_number}\n',
                      f'Expected Data: {og_icmp_data}  |  Reply Data: {reply_icmp_data}')
                time.sleep(1)
                return False
            return True


        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack(
                'I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(
                    b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 20    # original value: 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    # print("  *        *        *        *        *    Request timed out.")
                    raise timeout
                # recvPacket - bytes object representing data received
                recvPacket, addr = mySocket.recvfrom(1024)
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    # print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    raise timeout

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11 or icmpType == 3:                          # Time Exceeded
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(
                            recvPacket)
                        # if not self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket):
                        #     return False
                        icmpReplyPacket.printResultToConsole(
                            self.getTtl(), timeReceived, addr, self.__request_type, icmpType, pingStartTime)
                        # Echo reply is the end and therefore should return
                        return icmpReplyPacket, icmpType

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(
                            recvPacket)
                        if not self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket):
                            return False
                        icmpReplyPacket.printResultToConsole(
                            self.getTtl(), timeReceived, addr, self.__request_type, icmpType, pingStartTime)
                        # Echo reply is the end and therefore should return
                        return icmpReplyPacket, icmpType

                    else:
                        print("error")
            except timeout:
                print(f"TTL = {self.getTtl(
                )}        *                 *            *             *               Request timed out.")
                # Type 0, Code 16 is not real; I use it to identify a timeout:
                return (0, 16)
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        '''incoming ICMP reply'''

        __recvPacket = b''
        # default values before validity is checked:
        __isValidResponse = False
        __icmp_type_isvalid = False
        __icmp_code_isvalid = False
        __icmp_header_checksum_isvalid = False
        __icmp_date_time_sent_isvalid = False
        __icmp_identifier_isvalid = False
        __icmp_sequence_number_isvalid = False
        __icmp_data_isvalid = False
        __icmp_rtt = 0


        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # Getters:
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            # Used to track overall round trip time
            return self.__unpackByFormatAndPosition("d", 28)
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def get_icmp_type_isvalid(self):
            return self.__icmp_type_isvalid

        def get_icmp_code_isvalid(self):
            return self.__icmp_code_isvalid

        def get_icmp_header_checksum_isvalid(self):
            return self.__icmp_header_checksum_isvalid

        def get_icmp_date_time_sent_isvalid(self):
            return self.__icmp_date_time_sent_isvalid

        def get_icmp_identifier_isvalid(self):
            return self.__icmp_identifier_isvalid

        def get_icmp_sequence_number_isvalid(self):
            return self.__icmp_sequence_number_isvalid

        def get_icmp_data_isvalid(self):
            return self.__icmp_data_isvalid

        def get_icmp_rtt(self):
            return self.__icmp_rtt

        # Setters:
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def set_icmp_type_isvalid(self, booleanValue: bool):
            self.__icmp_type_isvalid = booleanValue

        def set_icmp_code_isvalid(self, booleanValue: bool):
            self.__icmp_code_isvalid = booleanValue

        def set_icmp_header_checksum_isvalid(self, booleanValue: bool):
            self.__icmp_header_checksum_isvalid = booleanValue

        def set_icmp_date_time_sent_isvalid(self, booleanValue: bool):
            self.__icmp_date_time_sent_isvalid = booleanValue

        def set_icmp_identifier_isvalid(self, booleanValue: bool):
            self.__icmp_identifier_isvalid = booleanValue

        def set_icmp_sequence_number_isvalid(self, booleanValue: bool):
            self.__icmp_sequence_number_isvalid = booleanValue

        def set_icmp_data_isvalid(self, booleanValue: bool):
            self.__icmp_data_isvalid = booleanValue

        def set_icmp_rtt(self, time: float):
            self.__icmp_rtt = int(time)

        # Private functions:
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # Public functions:
        def printResultToConsole(self, ttl, timeReceived, addr, sent_request_type, icmp_type=0, timeSent=0):
            imcp_message = get_icmp_message(
                str(self.getIcmpType()), str(self.getIcmpCode()))

            # Formatting for successful Ping responses:
            if icmp_type == 0 and sent_request_type == 'ping':
                bytes = struct.calcsize("d")
                timeSent = struct.unpack(
                    "d", self.__recvPacket[28:28 + bytes])[0]
                self.set_icmp_rtt((timeReceived - timeSent) * 1000)

                print(f'TTL = {ttl:<5}',
                      f'RTT = {((timeReceived - timeSent) * 1000)                               :>5.0f} {"ms":<5}',
                      f'Type = {self.getIcmpType():<5}',
                      f'Code = {self.getIcmpCode():<5}',
                      f'Identifier = {self.getIcmpIdentifier():<10}',
                      f'Sequence Number = {self.getIcmpSequenceNumber():<5}',
                      f'{addr[0]:<18}',
                      f'{imcp_message[0]} - {imcp_message[1]}')

            # Formatting for traceroute and non-0 ICMP types
            else:
                bytes = struct.calcsize("d")
                self.set_icmp_rtt((timeReceived - timeSent) * 1000)
                print(f'TTL = {ttl:<5}',
                      f'RTT = {((timeReceived - timeSent) * 1000)                               :>5.0f} {"ms":<5}',
                      f'Type = {self.getIcmpType():<5}',
                      f'Code = {self.getIcmpCode():<5}',
                      f'{addr[0]:<18}',
                      f'{imcp_message[0]} - {imcp_message[1]}')



    # True for verbose debugging
    __DEBUG_IcmpHelperLibrary = False

    # Initialize values for Ping:
    packets_to_send = 0
    packets_received = 0
    min_rtt = float('inf')
    max_rtt = float('-inf')
    total_rtt = 0

    # IcmpHelperLibrary Private Functions:
    def __sendIcmpEchoRequest(self, host, packetSequenceNumber, request_type, packet_ttl=255):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # Build packet
        icmpPacket = IcmpHelperLibrary.IcmpPacket()

        # Get as 16 bit number - Limit based on ICMP header standards
        randomIdentifier = (os.getpid() & 0xffff)
        # Some PIDs are larger than 16 bit

        packetIdentifier = randomIdentifier

        icmpPacket.buildPacket_echoRequest(
            packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
        icmpPacket.setTtl(packet_ttl)
        icmpPacket.set_request_type(request_type)

        icmpPacket.setIcmpTarget(host)

        # Save reply in a variable.
        # This is a tuple containing the reply packet and the reply ICMP code
        # Build IP
        reply = icmpPacket.sendEchoRequest()

        icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
        icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
        # we should be confirming values are correct, such as identifier and sequence number and data

        try:
            # Valid ICMP:
            if reply[0]:
                if reply[1] == 0:
                    self.packets_received += 1
                if reply[0].get_icmp_rtt() > self.max_rtt:
                    self.max_rtt = reply[0].get_icmp_rtt()
                if reply[0].get_icmp_rtt() < self.min_rtt:
                    self.min_rtt = reply[0].get_icmp_rtt()
                self.total_rtt += reply[0].get_icmp_rtt()
        except:
            pass
        finally:
            return reply


    def sendPing(self, targetHost):
        '''sends ICMP type 8, echo request'''
        print("ping started with debug") if self.__DEBUG_IcmpHelperLibrary else 0

        print(f'Ping started for {targetHost}\n',
              'Application will send ICMP packet once per second\n',
              '\n--- Press esc key to stop pinging ---\n')

        # Start and interrupt the main Ping while loop:
        self.ping_looping = True

        def end_loop():
            print('\nPing loop exiting')
            self.ping_looping = False
        keyboard.add_hotkey('esc', end_loop)

        # main loop:
        sequence_number = 0
        while self.ping_looping:
            self.__sendIcmpEchoRequest(targetHost, sequence_number, "ping")
            self.packets_to_send += 1
            sequence_number += 1
            time.sleep(1)

        print(f'\n\n ----- Ping to {targetHost} complete -----')
        print(f' {self.packets_to_send} packets transmitted\n',
              f'{self.packets_received} packets received\n',
              f'{((self.packets_to_send - self.packets_received) / self.packets_to_send) * 100:.2f}% Packet Loss\n')
        if self.packets_received > 0:
            print(f' Min RTT: {self.min_rtt} ms\n',
                  f'Max RTT: {self.max_rtt} ms\n',
                  f'Avg RTT: {int(self.total_rtt / self.packets_received)} ms')
        else:
            print(f' No replies received from {targetHost}.')
        print(' -----------------------------------\n')
        return

    def traceRoute(self, targetHost):
        '''sends ICMP echo requests with progressively increasing TTLs'''
        print("traceRoute started with debug") if self.__DEBUG_IcmpHelperLibrary else 0
        print(f'Traceroute started for {targetHost}\n')

        # Initial values
        sequence_number = 0
        packet_ttl = 1
        reply_type = True
        timeout_counter = 0

        # When reply_type is 0, returns False, and we exit the loop:
        while reply_type:
            # Reply variable is a tuple; the packet and the type number
            reply = self.__sendIcmpEchoRequest(
                targetHost, sequence_number, "traceroute", packet_ttl)
            time.sleep(1)
            reply_type = reply[1]
            # Timeout error:
            if reply_type == 16:
                timeout_counter += 1
                # Continues traceroute to next TTL after 3 timeouts
                if timeout_counter >= 3:
                    timeout_counter = 0
                    sequence_number += 1
                    packet_ttl += 1
                    print('Continuing at next in sequence')
                continue

            if reply_type in [3, 16]:
                sequence_number += 1
                packet_ttl += 1
                continue
            sequence_number += 1
            packet_ttl += 1
            timeout_counter = 0

        print("TRACEROUTE COMPLETE")


def main():
    '''Mostly used for build and troublshooting'''
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("35.211.233.246")
    # icmpHelperPing.sendPing("114.79.152.145")
    # icmpHelperPing.sendPing("www.google.com")
    icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.sendPing("ip-paris.fr")

    # icmpHelperPing.traceRoute("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("ip-paris.fr")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("www.google.com")
    # icmpHelperPing.traceRoute("114.79.152.145")
    # icmpHelperPing.traceRoute("amazon.co.uk")
    # icmpHelperPing.traceRoute("amazon.com")
    # icmpHelperPing.traceRoute("203.110.243.180")
if __name__ == "__main__":
    main()
