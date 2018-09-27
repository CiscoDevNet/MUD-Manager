import http.server
from http import HTTPStatus
import socketserver
import ssl
import sys, getopt
import os

class Server(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):

        request = self.path[1:]  # strip off leading /
        basename = os.path.basename(request)
        ext = os.path.splitext(basename)

        #print(self.headers)
        print("ServerRequest: {0}".format(request))

        is_signed = ext[1] == ".p7s"

        try:
            fp = open(request, "rb")
        except:
            self.send_error(404)
            print("Unable to open file {0}".format(request))
        else:
            stuff = fp.read()
            if not is_signed:
                print(stuff)

            try:
                self.send_response(HTTPStatus.OK)
                if is_signed:
                    self.send_header("Content-Type", "application/pkcs7-signature")
                else:
                    self.send_header("Content-Type", "application/mud+json")
                self.end_headers()
                self.wfile.write(stuff)
                print("Response is sent")
            except:
                print("Error in writing respone")

        print("done")
        return


def main(argv):
	certfile = ''
	keyfile = ''
	port = 443
	try:
            opts, args = getopt.getopt(argv,"c:k:p:")
	except getopt.GetoptError:
		print('mud_https_server.py -c <certfile> -k <keyfile> [-p <port>]')
	for opt,arg in opts:
		if opt == '-c':
			certfile = arg
		elif opt == '-k':
			keyfile = arg
		elif opt == '-p':
			port = int(arg)
	print('Certfile is:', certfile)
	print('Keyfile is:', keyfile)

	httpd = http.server.HTTPServer(('', port), Server) 
	print("Starting HTTP Server")
	httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=keyfile, certfile=certfile, server_side=True)
	httpd.serve_forever()

if __name__ == "__main__":
	main(sys.argv[1:])


