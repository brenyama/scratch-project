import React, { Component, useState, useEffect } from 'react';
import { connect } from 'react-redux';
import { NavLink } from 'react-router-dom';
import { useSelector } from "react-redux";
import { useDispatch } from "react-redux";
import CategoryCard from '../components/CategoryCard.jsx';
import NavBar from '../components/NavBar.jsx';
import TimerModal from '../components/TimerModal.jsx';
import { login } from '../actions/actions';

const MainContainer = () => {
  const props = useSelector(state => state);
  const [isFetch, setIsFetch] = useState(true);
  const dispatch = useDispatch(); 
  console.log(props)
  // loging not working fake data
  useEffect(() => {
    console.log('using effect')
    if(isFetch === true){
    const reqData = { 
      username: 'tom',
      password: 'tompassword'
    }
    fetch('/api/', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(reqData)})
      .then((res) => {
        return res.json();
      })
      .then((data) => {
        const payload = {};
        payload.user = data.user;
        payload.projects = data.projects;
        payload.categories = data.categories;
        payload.timerActivity = data.timerHistory;

        dispatch(login(payload))
        
      })
      setIsFetch(false)
    } 
  })
  
  const categoryElems = props.categories.map((info, key) => {
    return (
      <CategoryCard
        key={'category'+key}
        id={'category'+key}
        info={info}
        user={props.user}
        projects={props.projects}
        timerActivity={props.timerActivity}
        endTimer={props.endTimer}
        startTimer={props.startTimer}
      />
    );
  });

  return (
      <div id="mainDiv">
        <NavBar 
          id="navMain"
          user={props.user}
        />
        <div id="graf">
        {/* <img src='https://i.imgur.com/8MmE3tY.png' height="300px" /> */}
        </div>
        <div className="mainSection">
          <div id="sideBar">
          <button className='buttonSide'>Add Project</button>
          <button className='buttonSide'>Delete Project</button>
          <button className='buttonSide'>Conclude Project</button>
          <TimerModal
              id="timer"
              currentProjectName = {props.currentProjectName}
              currentCategoryName = {props.currentCategoryName}
              startTimer={props.startTimer}
              endTimer={props.endTimer} 
            />
          </div>
          <div className="cardsContainer">
            {categoryElems}
          </div>
        </div>
      </div>
    );
}

export default MainContainer;

/* 
const data = {
          user: {
              _id: 1,
              account_name: 'tom',
          },
          projects: [{
              _id: 1,
              title: 'Not specified',
            }, {           
              _id: 2,
              title: 'Project 1',
            }],
            categories: [{
              _id: 1,
              title: 'Coding',
            }, {
              _id: 2,
              title: 'Debug',
            }, {
              _id: 3,
              title: 'Meetings',
            }, {
              _id: 4,
              title: 'QA',
            }, {
              _id: 5,
              title: 'Code Review',
            }, {
              _id: 6,
              title: 'Reasearch',
            }, {
              _id: 7,
              title: 'Write Documentation',
            }, {
              _id: 8,
              title: 'Other',
            }],
            timerHistory: [{
              time_spent: 5000,
              updated_at: new Date().toString(),
              category_id: 3,
              project_id: 2,
            }, {
              time_spent: 4000,
              updated_at: new Date().toString(),
              category_id: 1,
              project_id: 2,
            }, {
              time_spent: 2000,
              updated_at: new Date().toString(),
              category_id: 3,
              project_id: 1,
            }, {
              time_spent: 4000,
              updated_at: new Date().toString(),
              category_id: 2,
              project_id: 2,
            }]
          }
*/