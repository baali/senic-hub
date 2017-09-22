from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from pytest import fixture, raises

import responses

from senic_hub.backend.device_discovery import (
    add_authentication_status,
    add_device_details,
    add_homeassistant_entity_ids,
    discover_devices,
    discover_and_merge_devices,
    get_device_description,
    merge_devices,
    PhilipsHueBridgeApiClient,
    UnsupportedDeviceTypeException,
    UpstreamError,
)
from senic_hub.backend.testing import temp_asset_path


@patch('senic_hub.backend.device_discovery.discover_devices')
@patch('senic_hub.backend.device_discovery.add_authentication_status')
@patch('senic_hub.backend.device_discovery.add_device_details')
@patch('senic_hub.backend.device_discovery.add_homeassistant_entity_ids')
def test_devices_are_discovered_and_merged_with_existing_devices_file(
        add_homeassistant_entity_ids_mock, add_device_details_mock,
        add_authentication_status_mock, discover_devices_mock):
    discover_devices_mock.return_value = []
    with temp_asset_path('devices.json') as devices_path:
        discover_and_merge_devices(devices_path, datetime.utcnow())
    # TODO: `assert_called (_once)` only available on the mock with Python 3.6, we use Python 3.5
    # add_homeassistant_entity_ids_mock.assert_called_once()
    # add_device_details_mock.assert_called_once()
    # add_authentication_status_mock.assert_called_once()
    # discover_devices_mock.assert_called_once()


@patch('senic_hub.backend.device_discovery.discover_devices')
@patch('senic_hub.backend.device_discovery.add_authentication_status')
@patch('senic_hub.backend.device_discovery.add_device_details')
@patch('senic_hub.backend.device_discovery.add_homeassistant_entity_ids')
def test_devices_are_discovered_and_merged_with_empty_devices_file(
        add_homeassistant_entity_ids_mock, add_device_details_mock,
        add_authentication_status_mock, discover_devices_mock):
    discover_devices_mock.return_value = []
    with temp_asset_path('empty') as devices_path:
        discover_and_merge_devices(devices_path, datetime.utcnow())
    # TODO: `assert_called_once` only available with Python 3.6, we use Python 3.5
    # add_homeassistant_entity_ids_mock.assert_called_once()
    # add_device_details_mock.assert_called_once()
    # add_authentication_status_mock.assert_called_once()
    # discover_devices_mock.assert_called_once()


def test_add_authentication_status_sets_authenticated_if_authentication_not_required():
    device = dict(authenticationRequired=False)
    add_authentication_status([device])
    assert(device['authenticated'])


def test_add_authentication_status_sets_authenticated_if_authentication_required_for_non_philips_hue_device():
    device = dict(authenticationRequired=True, type='no-philips-hue')
    add_authentication_status([device])
    assert(device['authenticated'])


@patch.object(PhilipsHueBridgeApiClient, 'is_authenticated')
def test_add_authentication_status_sets_authenticated_if_philips_hue_api_says_yes(is_authenticated_mock):
    is_authenticated_mock.return_value = True
    device = dict(ip='0.0.0.0', type='philips_hue', authenticationRequired=True, extra=dict())
    add_authentication_status([device])
    assert(device['authenticated'])


@patch.object(PhilipsHueBridgeApiClient, 'is_authenticated')
def test_add_authentication_status_sets_authenticated_if_philips_hue_api_says_no(is_authenticated_mock):
    is_authenticated_mock.return_value = False
    device = dict(ip='0.0.0.0', type='philips_hue', authenticationRequired=True, extra=dict())
    add_authentication_status([device])
    assert(not device['authenticated'])


@patch.object(PhilipsHueBridgeApiClient, 'get_lights')
def test_add_device_details_adds_philips_hue_lights(get_lights_mock):
    expected = 'foo'
    get_lights_mock.return_value = expected
    device = dict(ip='0.0.0.0', type='philips_hue', authenticated=True, extra=dict(username='foo'))
    add_device_details([device])
    assert(device['extra']['lights'] == expected)


def test_add_homeassistant_entity_ids_adds_philips_hue():
    device = dict(type='philips_hue')
    add_homeassistant_entity_ids([device])
    assert(device['ha_entity_id'] == 'light.senic_hub')


def test_add_homeassistant_entity_ids_adds_soundtouch():
    device = dict(type='soundtouch')
    add_homeassistant_entity_ids([device])
    assert(device['ha_entity_id'] == 'media_player.bose_soundtouch')


def test_add_homeassistant_entity_ids_adds_sonos():
    device = dict(type='sonos', extra=dict(roomName='foo'))
    add_homeassistant_entity_ids([device])
    assert(device['ha_entity_id'] == 'media_player.foo')


def test_add_homeassistant_entity_ids_throws_exception_for_unknown_device_type():
    device = dict(type='no-such-type')
    with raises(UnsupportedDeviceTypeException):
        add_homeassistant_entity_ids([device])


@fixture
def philips_hue_bridge_device_info():
    return ("", "http://127.0.0.1:80/")


@fixture
def sonos_device_info():
    return "192.168.1.42"


@fixture
def soundtouch_device_info():
    return ("192.168.1.23", 8090)


@responses.activate
def test_get_device_description_of_philips_hue_bridge(philips_hue_bridge_device_info, philips_hue_bridge_description):
    responses.add(responses.GET, 'http://127.0.0.1:80/description.xml', body=philips_hue_bridge_description, status=200)
    expected = {
        "id": "ph1",
        "name": "Philips Hue bridge",
        "authenticationRequired": True,
        "type": "philips_hue",
        "ip": "127.0.0.1",
        "extra": {},
    }
    assert get_device_description("philips_hue", philips_hue_bridge_device_info) == expected


@responses.activate
def test_get_device_description_of_philips_hue_bridge_throws_when_getting_description_fails(philips_hue_bridge_device_info):
    responses.add(responses.GET, 'http://127.0.0.1:80/description.xml', status=404)
    with raises(UpstreamError) as e:
        get_device_description("philips_hue", philips_hue_bridge_device_info)
    assert e.value.error_type == 404


@responses.activate
def test_get_device_description_of_sonos_speaker(sonos_device_info, sonos_speaker_description):
    responses.add(responses.GET, 'http://192.168.1.42:1400/xml/device_description.xml', body=sonos_speaker_description, status=200)
    expected = {
        "id": "123",
        "type": "sonos",
        "ip": "192.168.1.42",
        "authenticationRequired": False,
        "name": "192.168.1.42 Foo Bar",
        "extra": {
            "roomName": "Foo Bar",
        },
    }
    assert get_device_description("sonos", sonos_device_info) == expected


@responses.activate
def test_get_device_description_of_soundtouch_speaker(soundtouch_device_info):
    expected = {
        "id": "192_168_1_23",
        "type": "soundtouch",
        "ip": "192.168.1.23",
        "port": 8090,
        "authenticationRequired": False,
        "name": "Bose Soundtouch",
        "extra": {},
    }
    assert get_device_description("bose_soundtouch", soundtouch_device_info) == expected


@responses.activate
def test_get_device_description_of_sonos_speaker_throws_when_getting_description_fails(sonos_device_info):
    responses.add(responses.GET, 'http://192.168.1.42:1400/xml/device_description.xml', status=404)
    with raises(UpstreamError) as e:
        get_device_description("sonos", sonos_device_info)
    assert e.value.error_type == 404


class MockPhilipsDiscovery(MagicMock):
    def scan(self):
        pass

    def stop(self):
        pass

    def discover(self):
        return ["philips_hue"]

    def get_info(self, device_type):
        return [("", "http://127.0.0.1:80/")]


@responses.activate
def test_discover_philips_hue_device(philips_hue_bridge_description):
    responses.add(responses.GET, 'http://127.0.0.1:80/description.xml', body=philips_hue_bridge_description, status=200)
    expected = {
        "id": "ph1",
        "name": "Philips Hue bridge",
        "authenticationRequired": True,
        "type": "philips_hue",
        "ip": "127.0.0.1",
        "extra": {},
    }
    assert discover_devices(MockPhilipsDiscovery) == [expected]


def test_discover_devices_for_the_first_time_return_all_devices():
    known_devices = []
    discovered_devices = [{
        "id": "1",
        "name": "first",
    }, {
        "id": "2",
        "name": "second",
    }]
    now = datetime.utcnow()
    expected = [{
        "id": "1",
        "name": "first",
        'discovered': str(now),
    }, {
        "id": "2",
        "name": "second",
        'discovered': str(now),
    }]
    assert merge_devices(known_devices, discovered_devices, now) == expected


def test_discover_devices_includes_new_device_discovered():
    now = datetime.utcnow()
    known_devices = [{
        "id": "1",
        "name": "first",
        'discovered': str(now - timedelta(minutes=2)),
    }]
    discovered_devices = [{
        "id": "1",
        "name": "first",
    }, {
        "id": "2",
        "name": "second",
    }]
    expected = [{
        "id": "1",
        "name": "first",
        'discovered': str(now),
    }, {
        "id": "2",
        "name": "second",
        'discovered': str(now),
    }]
    assert merge_devices(known_devices, discovered_devices, now) == expected


def test_discover_devices_update_device_with_updated_fields():
    now = datetime.utcnow()
    known_devices = [{
        "id": "1",
        "name": "first",
        'discovered': str(now - timedelta(minutes=2)),
    }]
    discovered_devices = [{
        "id": "1",
        "name": "first updated",
    }, {
        "id": "2",
        "name": "second",
    }]
    expected = [{
        "id": "1",
        "name": "first updated",
        'discovered': str(now),
    }, {
        "id": "2",
        "name": "second",
        'discovered': str(now),
    }]
    assert merge_devices(known_devices, discovered_devices, now) == expected


def test_discover_devices_device_that_wasnt_discovered_again_is_not_removed_from_the_devices_list():
    now = datetime.utcnow()
    known_devices = [{
        "id": "1",
        "name": "first",
        'discovered': str(now),
    }, {
        "id": "2",
        "name": "second",
        'discovered': str(now),
    }]
    discovered_devices = [{
        "id": "1",
        "name": "first",
    }]
    expected = known_devices
    assert merge_devices(known_devices, discovered_devices, now) == expected


def test_merging_devices_keeps_hue_username():
    now = datetime.utcnow()
    known_devices = [{
        "id": "1",
        "type": "philips_hue",
        'discovered': str(now),
        'extra': {
            'username': 'light-bringer',
        },
    }, {
        "id": "2",
        "type": "philips_hue",
        'discovered': str(now),
        'extra': {
            'username': 'another-light-bringer',
        },
    }]
    discovered_devices = [{
        "id": "1",
        "type": "philips_hue",
    }, {
        "id": "2",
        "type": "philips_hue",
        'extra': {},
    }]
    expected = known_devices
    assert merge_devices(known_devices, discovered_devices, now) == expected
