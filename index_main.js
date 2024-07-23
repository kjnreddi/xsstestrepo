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
    console.log(req.body.userInput)
    console.log("--------------")
    const userInput = req.body.userInput.replace(/\\"/g, '"');;

    // Define custom options with a custom whitelist
    let customWhitelist = {
        a: ['href', 'title', 'target','rel','style'], // Only allow <a> tags with href, title, and target attributes
        iframe: ['width', 'height', 'src', 'frameborder', 'allow', 'allowfullscreen']
    };

    // Merge the custom whitelist with the default whitelist
    let options = {
        whiteList: Object.assign({}, xss.whiteList, customWhitelist)
    };

    const myxss = new xss.FilterXSS(options);
    const sanitizedInputxss = myxss.process(userInput);
    //const sanitizedInputxss = xss(userInput,options);  // Properly sanitize the input
    
    const sanitizedInput = sanitizedInputxss.replace(/"/g, '\\"');

    console.log(sanitizedInput)

    res.send(`<p>Sanitized Input:</p><p>${sanitizedInputxss}</p>`);
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});