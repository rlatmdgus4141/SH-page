import {readFileSync,writeFileSync} from 'node:fs';
const original=readFileSync('t08/T01_original.html','utf8'),section=readFileSync('t08/private-section.html','utf8');
const html=original.replace('</nav>','<a href="#private-space">개인 공간</a></nav>').replace('</head>','<link rel="stylesheet" href="/passkeys.css"><link rel="icon" href="/favicon.svg"></head>').replace('</main>',section+'\n</main>').replace('</body>','<script src="/webauthn.umd.js" defer></script><script src="/passkeys.js" defer></script></body>');
writeFileSync('lib/public-page.ts','export const publicPage = '+JSON.stringify(html)+';\n');
writeFileSync('lib/auth-guide.ts','export const authGuide = '+JSON.stringify(readFileSync('t08/AUTH_IMPLEMENTATION.md','utf8'))+';\n');
