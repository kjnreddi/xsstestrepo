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
    console.log(req.body.userInput);
    console.log("--------------");

    // Replace escaped quotes with actual quotes
    let userInput = req.body.userInput.replace(/\\"/g, '"');

    // Define custom options with a comprehensive custom whitelist
    let customWhitelist = {
        a: ['href', 'title', 'target', 'rel', 'style'], // Only allow <a> tags with these attributes
        iframe: ['width', 'height', 'src', 'frameborder', 'allow', 'allowfullscreen'], // Allow <iframe> tags with these attributes
        p: [],
        span: ['style'],
        div: ['style'],
        img: ['src', 'alt', 'width', 'height'],
        b: [],
        i: [],
        u: [],
        em: [],
        strong: [],
        ul: [],
        ol: [],
        li: [],
        br: [],
        h1: ['style'],
        h2: ['style'],
        h3: ['style'],
        h4: ['style'],
        h5: ['style'],
        h6: ['style'],
        // Ensure other potentially harmful tags like <object> are not included
    };

     // Create options for the FilterXSS instance
    let options = {
        whiteList: customWhitelist,
        stripIgnoreTag: true, // Filter out tags not in the whitelist
        stripIgnoreTagBody: ['script', 'object'] // Filter out <script> and <object> tags and their content
    };

    // Create a FilterXSS instance with the custom options
    const myxss = new xss.FilterXSS(options);

    // Sanitize the user input using the FilterXSS instance
    let sanitizedInput = myxss.process(userInput);

    // Debugging output
    console.log('Sanitized Input:', sanitizedInput);

    // Send the sanitized input back to the client
    res.send(`<p>Sanitized Input:</p><p>${sanitizedInput}</p>`);
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});