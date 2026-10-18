const router = require('express').Router();
const { calendar, CAL_ID } = require('../google');
const { requirePerm } = require('../rbac');

router.get('/events', requirePerm('calendar:read'), async (req, res) => {
  const r = await calendar.events.list({
    calendarId: CAL_ID, singleEvents: true, orderBy: 'startTime', maxResults: 250,
    timeMin: req.query.from || new Date().toISOString(), timeMax: req.query.to,
  });
  res.json(r.data.items);
});

router.post('/events', requirePerm('calendar:write'), async (req, res) => {
  const { title, description, start, end } = req.body; // start/end: {dateTime|date}
  const r = await calendar.events.insert({
    calendarId: CAL_ID,
    requestBody: { summary: title, description: `${description || ''}\n— creato da ${req.user.name}`, start, end },
  });
  res.json(r.data);
});

router.delete('/events/:id', requirePerm('calendar:write'), async (req, res) => {
  await calendar.events.delete({ calendarId: CAL_ID, eventId: req.params.id });
  res.json({ ok: true });
});

module.exports = router;
