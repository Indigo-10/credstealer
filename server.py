from http.server import BaseHTTPRequestHandler, HTTPServer

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"\n[+] Received POST Request:\n{post_data.decode()}\n")
        self.send_response(200)
        self.end_headers()

server_address = ('', 8000)
httpd = HTTPServer(server_address, RequestHandler)
print("[*] Listening for POST requests on port 8000...")
httpd.serve_forever()
