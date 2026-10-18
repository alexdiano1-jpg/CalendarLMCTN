const { google } = require('googleapis');

const redirectUri = `${process.env.BASE_URL}/auth/callback`;
const newClient = () =>
  new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, redirectUri);

// Client del Master Account: usato SOLO lato server, mai esposto agli utenti
const master = newClient();
master.setCredentials({ refresh_token: process.env.MASTER_REFRESH_TOKEN });

module.exports = {
  newClient,
  calendar: google.calendar({ version: 'v3', auth: master }),
  drive: google.drive({ version: 'v3', auth: master }),
  CAL_ID: process.env.MASTER_CALENDAR_ID || 'primary',
  ROOT_ID: process.env.NOTES_ROOT_FOLDER_ID,
};
