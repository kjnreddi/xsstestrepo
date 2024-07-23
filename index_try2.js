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

    // Default whitelist from xss library
    const defaultWhitelist = xss.whiteList;

    // Custom whitelist to merge
    let customWhitelist = {
        a: ['href', 'title', 'target', 'rel', 'style'],
        iframe: ['width', 'height', 'src', 'frameborder', 'allow', 'allowfullscreen'],
    };

    // Deep copy the default whitelist
    let mergedWhitelist = JSON.parse(JSON.stringify(defaultWhitelist));

    // Merge custom whitelist into the copied default whitelist
    Object.keys(customWhitelist).forEach(tag => {
        if (mergedWhitelist[tag]) {
            // If the tag exists in the default whitelist, merge attributes
            mergedWhitelist[tag] = Array.from(new Set([...mergedWhitelist[tag], ...customWhitelist[tag]]));
        } else {
            // If the tag does not exist in the default whitelist, add it
            mergedWhitelist[tag] = customWhitelist[tag];
        }
    });

    // Define options with the merged whitelist
    let options = {
        whiteList: mergedWhitelist
    };

    // Create a FilterXSS instance with the custom options
    let myxss = new xss.FilterXSS(options);

    // Sanitize the user input using the FilterXSS instance
    const sanitizedInput = myxss.process(userInput);
    res.send(`<p>Sanitized Input:</p><p>${sanitizedInput}</p>`);
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});