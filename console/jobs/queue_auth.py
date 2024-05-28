from firebase_admin import firestore

from celery import shared_task

from configs import variable_system as var_sys

from helpers import helper

@shared_task
def update_avatar(user_id, avatar_url):
    if not avatar_url:
        avatar_url = var_sys.AVATAR_DEFAULT['AVATAR']
    database = firestore.client()
    account_ref = database.collection('accounts').document(str(user_id))

    try:
        account_doc = account_ref.get()
        if account_doc.exists:
            account = account_doc.to_dict()
            update_data = {
                'avatar_url': avatar_url
            }

            if account['company']:
                update_data.update({'company.imageUrl': avatar_url})
            account_ref.update(update_data)
    except Exception as ex:
        helper.print_log_error('update_avatar', ex)