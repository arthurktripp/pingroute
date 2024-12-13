# Types and Codes from https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-11
# JSON is my own - Arthur

icmp_types_codes = {
    "0": {
        "type": "Echo Reply",
        "0": "Success"
    },
    "3": {
        "type": "Destination Unreachable",
        "0": "Net Unreachable",
        "1": "Host Unreachable",
        "2": "Protocol Unreachable",
        "3": "Port Unreachable",
        "4": "Fragmentation Needed and Don't Fragment was Set",
        "5": "Source Route Failed",
        "6": "Destination Network Unknown",
        "7": "Destination Host Unknown",
        "8": "Source Host Isolated",
        "9": "Communication with Destination Network is Administratively Prohibited",
        "10": "Communication with Destination Host is Administratively Prohibited",
        "11": "Destination Network Unreachable for Type of Service",
        "12": "Destination Host Unreachable for Type of Service",
        "13": "Communication Administratively Prohibited",
        "14": "Host Precedence Violation",
        "15": "Precedence cutoff in effect"
    },
    "8": {
        "type": "Echo",
        "0": "No Code"
    },
    "11": {
        "type": "Time Exceeded",
        "0": "Time to Live exceeded in Transit",
        "1": "Fragment Reassembly Time Exceeded"
    }
}

def get_icmp_message(type, code):
    return icmp_types_codes[type]["type"], icmp_types_codes[type][code]