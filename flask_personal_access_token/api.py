# -*- coding: utf-8 -*-

import pyotp
from flask import Blueprint, current_app, jsonify, request, redirect, url_for
from .model import PersonalAccessToken, TotpSecretKey

bp = Blueprint('personal_access_token.api', __name__)

@bp.before_request
def before_request():
    return bp.app.call_before_request_funcs()

@bp.route('/tokens')
def get_tokens():
    tokens = PersonalAccessToken.query.filter_by(user_id=bp.app.current_user_id).all()
    return ok([token.to_dict() for token in tokens])


@bp.route('/tokens', methods=['POST'])
def create_token():
    user_id = bp.app.current_user_id
    data = _get_form_data()
    if not data:
        return bad_request()
    description = data['description']
    scopes = data['scopes']
    token = PersonalAccessToken.add(user_id, description, scopes)
    return ok(token.to_full_dict())

@bp.route('/tokens/<int:id>')
def get_token(id):
    token = PersonalAccessToken.query.get(id)
    error = _validate_token(token)
    if error:
        return error
    data = token.to_dict()
    return ok(data)

@bp.route('/tokens/<int:id>', methods=['DELETE'])
def delete_token(id):
    token = PersonalAccessToken.query.get(id)
    error = _validate_token(token)
    if error:
        return error
    token.delete()
    return ok()

@bp.route('/tokens/<int:id>', methods=['PUT'])
def update_token(id):
    token = PersonalAccessToken.query.get(id)
    error = _validate_token(token)
    if error:
        return error
    data = _get_form_data()
    if not data:
        return bad_request()
    description = data['description']
    scopes = data['scopes']
    token = token.update(description, scopes)
    return ok(token.to_dict())


@bp.route('/totp_keys', methods=['GET', 'POST'])
def totp_key():
    user_id = bp.app.current_user_id
    if request.method == 'GET':
        key = TotpSecretKey.get_by_user(user_id=user_id)
        if not key:
            return ok([])
        totp = pyotp.TOTP(key['secret_key'])
        key['url'] = totp.provisioning_uri(str(user_id))
        return ok([key])
    else:
        data = _get_form_data()
        key = TotpSecretKey.get_by_user(user_id=user_id)
        if key:
            return bad_request()
        TotpSecretKey.add(user_id=user_id, description=data['description'])
        return ok()


@bp.route('/totp_keys/<int:id>')
def get_key(id):
    key = TotpSecretKey.query.get(id)
    error = _validate_token(key)
    if error:
        return error
    data = key.to_dict()
    return ok(data)


@bp.route('/totp_keys/<int:id>', methods=['DELETE'])
def delete_key(id):
    key = TotpSecretKey.query.get(id)
    error = _validate_token(key)
    if error:
        return error
    key.delete()
    return ok()


def _get_form_data():
    data = request.get_json()
    if not data:
        return
    if 'description' not in data:
        return
    scopes = data.get('scopes')
    scopes = scopes or []
    if not isinstance(scopes, list):
        return
    for scope in scopes:
        if not isinstance(scope, str) and scope:
            return
    description = data['description']
    return dict(scopes=scopes, description=description)

def _validate_token(token):
    if not token:
        return not_found()
    if token.user_id != bp.app.current_user_id:
        return forbidden()

def bad_request():
    return jsonify(), 400

def not_found():
    return jsonify(), 404

def forbidden():
    return jsonify(), 403

def ok(data=None):
    return jsonify(data=data)
