import EBay from '../../src';
// @ts-ignore
import readline from 'readline';

const ebay = EBay.fromEnv();
// DOCS: https://developer.ebay.com/devzone/xml/docs/howto/tokens/gettingtokens.html

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

ebay.authNAuth.getSessionIdAndAuthUrl().then(({url, sessionId}) => {
    console.log('Authorize this app by visiting this url: ', url);

    rl.question('Press Enter after grant access', async () => {
        const token = await ebay.authNAuth.fetchAuthToken(sessionId);
        ebay.authNAuth.setAuthToken(token);

        const time = await ebay.trading.GeteBayOfficialTime();
        console.log(time);

        rl.close();
    });
});
