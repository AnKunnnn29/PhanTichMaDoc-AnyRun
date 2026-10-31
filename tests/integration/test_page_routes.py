import pytest
from app import app
from ir_workspace.web.pages import PAGE_PATHS


@pytest.mark.parametrize('path', PAGE_PATHS)
def test_screen_can_be_opened_directly(path):
    response = app.test_client().get(path)
    assert response.status_code == 200
    assert b'/static/navigation.js' in response.data
    assert b'page-overview' in response.data


def test_unknown_screen_does_not_mask_missing_api():
    client = app.test_client()
    assert client.get('/analyze/unknown').status_code == 404
    assert client.get('/api/unknown').status_code == 404
    assert client.get('/history/').status_code == 200
