from subprocess import call
import platform
import sys

def rule(ip, port):
    return "block drop out quick proto tcp to %s port = %s flags R/R" % (ip, port)

def main():
    if not ((len(sys.argv) == 3 and sys.argv[1] == "setup") or (len(sys.argv) == 2) and sys.argv[1] == "teardown"):
        print "Usage: python firewall.py (setup [server IP]|teardown)"
        exit()

    if sys.argv[1] == "setup":
        if platform.system() == "Darwin":
            call("(cat /etc/pf.conf; echo '%s\n%s\n%s') | sudo pfctl -ef -" % \
                (rule(sys.argv[2],80),rule(sys.argv[2],443),rule(sys.argv[2],34343)), shell=True)
            print "Middlebox firewall tests have been added, and pf enabled."
    elif sys.argv[1] == "teardown":
        if platform.system() == "Darwin":
            call("sudo pfctl -f /etc/pf.conf", shell=True)
            print "Middlebox firewall tests have been removed."
            print "Do you want pf to be [e]nabled or [d]isabled?",
            call("sudo pfctl -%s" % ("e" if raw_input() == "e" else "d"), shell=True)

if __name__ == "__main__":
    main()
