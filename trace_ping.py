from IcmpHelperLibrary1 import IcmpHelperLibrary


def main():
    print("\n****************************************",
          "\nExecute a Traceroute or Ping to a server",
          "\n****************************************\n")
    method = input("Press 1 for Traceroute or 2 for Ping: ")

    if method not in ['1', '2']:
        print('Invalid choice')
        return False

    host = input("Please enter a valid hostname or IPv4 address: ")

    icmpLibrary = IcmpHelperLibrary()

    if method == "1":
        icmpLibrary.traceRoute(host)
    elif method == "2":
        icmpLibrary.sendPing(host)


if __name__ == "__main__":
    main()
