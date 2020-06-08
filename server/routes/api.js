const express = require('express');
const router = express.Router();

const projectsController = require('../controllers/projectsController.js')
const categoryController = require('../controllers/categoryController.js')
const timerHistoryController = require('../controllers/timerHistoryController.js')
const userController = require('../controllers/userController.js')

router.post('/', userController.validateUser, categoryController.getCategory, projectsController.getProjects, timerHistoryController.getTimerHistory, (req, res) => {
  res.status(200).json({
    user: res.locals.user,
    categories: res.locals.categories,
    projects: res.locals.projects,
    timerHistory: res.locals.timerHistory
  });
})

module.exports = router;