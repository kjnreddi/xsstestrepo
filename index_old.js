const express = require('express');
const xss = require('xss');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.post('/sanitize', (req, res) => {
    const userInput = req.body.userInput;
    const sanitizedInput = xss(userInput);  // Properly sanitize the input
    res.send(`<p>Sanitized Input:</p><p>${sanitizedInput}</p>`);
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});