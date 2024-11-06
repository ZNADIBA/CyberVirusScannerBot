<<<<<<< HEAD
﻿const http = require('http');

const hostname = '127.0.0.1'; // Your local address
const port = 3000; // The port your server will listen to

const server = http.createServer((req, res) => {
    res.statusCode = 200; // HTTP status code for success
    res.setHeader('Content-Type', 'text/plain'); // Set response type
    res.end('Hello, this is your chatbot! What can I help you with?'); // Response body
});

server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});
=======
﻿const http = require('http');

const hostname = '127.0.0.1'; // Your local address
const port = 3000; // The port your server will listen to

const server = http.createServer((req, res) => {
    res.statusCode = 200; // HTTP status code for success
    res.setHeader('Content-Type', 'text/plain'); // Set response type
    res.end('Hello, this is your chatbot! What can I help you with?'); // Response body
});

server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});
>>>>>>> b37c755 (Merge remote changes)
