const express = require('express');
const router = express.Router();

const timerHistoryController = require('../controllers/timerHistoryController.js')

router.post('/', timerHistoryController.createTimerEntry, timerHistoryController.getTimerHistory, (req, res) => {
  res.status(201).json(res.locals.timerHistory);
})

router.get('/', timerHistoryController.getTimerHistory, (req, res) => {
  res.status(201).json(res.locals.timerHistory);
})

module.exports = router;
