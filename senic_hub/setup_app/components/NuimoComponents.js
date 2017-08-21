import React from 'react';
import { FlatList } from 'react-native';
import { List, ListItem } from 'react-native-elements';
import Screen from './Screen'
import Settings from '../Settings'

import Swipeout from 'react-native-swipeout';


export default class NuimoComponents extends Screen {
  constructor(props) {
    super(props)

    this.state = {
      components: [],
    }

    this.setTitle(this.props.name)
    this.setNavigationButtons([], [
      {
        title: "Add Device",
        id: 'add',
        onPress: () => this.pushScreen('app.addComponent', { nuimoId: this.props.nuimoId })
      }
    ])
  }

  didAppear() {
    this.fetchComponents()
  }

  fetchComponents() {
    fetch(Settings.HUB_API_URL + 'nuimos/' + this.props.nuimoId + '/components')
      .then((response) => {
        if (!response.ok) {
          throw new Error('Request failed: ' + JSON.stringify(response))
        }
        return response.json()
      })
      .then((components) => {
        this.setState({ components: components.components })
      })
      .catch((error) => console.error(error))
  }

  renderRow(item) {
    let swipeBtns = [{
       text: 'Delete',
       backgroundColor: 'red',
       underlayColor: 'rgba(0, 0, 0, 0.6)',
       onPress: () => {
         alert(
           'Delete Component',
           'Are you sure?',
           [
             {text: 'Cancel', style: 'cancel'},
             {text: 'Delete', onPress: this.deleteComponent(item.id)},
           ],
           { cancelable: false }
         )
       }
    }];

    return (
      <Swipeout right={swipeBtns}
        autoClose={true}
        backgroundColor='transparent'>
        <ListItem
          title={item.name}
          onPress={() => {
            this.pushScreen('app.deviceSelection', {nuimoId: this.props.nuimoId, component: item})
          }} />
      </Swipeout>
    );
  }


  render() {
    return (
      <List>
        <FlatList
          data={this.state.components}
          renderItem={({item}) => this.renderRow(item)}
          keyExtractor={(components) => components.id}
        />
      </List>
    );
  }


  deleteComponent(itemId){
    component = {}
    let body = JSON.stringify(component)
    let params = {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
      body: body,
    }
    url = Settings.HUB_API_URL + 'nuimos/' + this.props.nuimoId + '/components/' + itemId
    return fetch(url, params)
      .then(response => {
        if (!response.ok) {
          throw new Error('Deleting component failed with status: ' + response.status)
        } else {
          this.fetchComponents()
        }
      })
  }

}
