import * as types from '../constants/constantsType';

const initialState = {
  user: {},
  projects: [],
  categories: [],
  timerActivity: [],
  currentProjectName:'',
  currentCategoryName:'',
  currentProjectId: 0,
  currentCategoryId: 0,
  startTimer: 0,
  endTimer: 0,
  lastInterval: 0,
};

const mainReducer = (state = initialState, action) => {
  let user;
  let projects;
  let categories;
  let timerActivity;
  let currentProjectName;
  let currentCategoryName;
  let currentProjectId;
  let currentCategoryId;
  let startTimer;
  let endTimer;
  let lastInterval;

  switch (action.type) {      
    case types.LOGIN:
      user = action.payload.user;
      projects = action.payload.projects;
      categories = action.payload.categories;
      timerActivity = action.payload.timerActivity;

      return {
        ...state,
        user,
        projects,
        categories,
        timerActivity,
      };
    
    case types.SIGNUP:
      user = action.payload.user;
      projects = action.payload.Project;
      categories = action.payload.Category;
  
      return {
        ...state,
        user,
        projects,
        categories,
      };

    case types.LOGOUT:
      user = initialState.user;
      projects = initialState.projects;
      categories = initialState.categories;
      timerActivity = initialState.timerActivity;
      currentProjectName = initialState.currentProjectName;
      currentCategoryName = initialState.currentCategoryName;
      currentProjectId = initialState.currentProjectId;
      currentCategoryId = initialState.currentCategoryId;
      startTimer = initialState.startTimer;
      endTimer = initialState.endTimer;
      lastInterval = initialState.lastInterval;
  
      return {
        ...state,
        user ,
        projects,
        categories,
        timerActivity,
        currentProjectName,
        currentCategoryName,
        currentProjectId,
        currentCategoryId,
        startTimer,
        endTimer,
        lastInterval,
      };

    case types.ADD_PROJECT:
      projects = state.projects.slice();
      projects.push(action.payload.projects);

      return {
        ...state,
        projects,
      };

    case types.DELETE_PROJECT:
      projects = [];
      for (let project of state.projects){
        if(project !== action.payload.projects){
          projects.push(project);
        } 
      }

      return {
        ...state,
        projects,
      };

    case types.COMPLETE_PROJECT:
      projects = [];
      for (let project of state.projects){
        if(project !== action.payload.projects){
          projects.push(project);
        } 
      }

      return {
        ...state,
        projects,
      };

    case types.ADD_CATEGORY:
      categories = state.categories.slice();
      categories.push(action.payload.categories);

      return {
        ...state,
        categories,
      };

    case types.DELETE_CATEGORY:
      categories = [];
      for (let category of state.categories){
        if(category !== action.payload.categories){
          categories.push(category);
        } 
      }

      return {
        ...state,
        categories,
      };

    case types.PLAY_TIMER:
      startTimer = Date.now();
      endTimer = initialState.startTimer;
      currentProjectName = action.payload.currentProjectName;
      currentCategoryName = action.payload.currentCategoryName;
      currentProjectId = action.payload.currentProjectId;
      currentCategoryId = action.payload.currentCategoryId;

      return {
        ...state,
        currentProjectName,
        currentCategoryName,
        currentProjectId,
        currentCategoryId,
        startTimer,
        endTimer,
      };

    case types.STOP_TIMER:
      endTimer = Date.now();
      lastInterval = endTimer - startTimer;
      startTimer = 0;
      currentProjectName = initialState.currentProjectName;
      currentCategoryName = initialState.currentCategoryName;
      currentProjectId = initialState.currentProjectId;
      currentCategoryId = initialState.currentCategoryId;
      timerActivity = state.timerActivity.slice();
      timerActivity.push(action.payload.timerActivity);

      return {
        ...state,
        timerActivity,
        currentProjectName,
        currentCategoryName,
        currentProjectId,
        currentCategoryId,
        startTimer,
        endTimer,
        lastInterval,
      };

    default:
      return state;
  }
};

export default mainReducer;
