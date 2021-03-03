from django.conf.urls import url, include
from django.urls import path
from django.contrib.auth import views as auth_views
from rest_framework.routers import SimpleRouter
from api import kb, staff, views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

router = SimpleRouter()
router.register(r'user', views.UserViewSet, 'User')
router.register(r'queue', views.QueueViewSet, 'Queue')
router.register(r'presetreply', views.PreSetReplyViewSet, 'PreSetReply')

urlpatterns = router.urls

urlpatterns += [
    url(r'^dashboard/$',
        staff.dashboard,
        name='dashboard'),

    url(r'^tickets/$',
        staff.ticket_list,
        name='list'),

    url(r'^tickets/submit/$',
        staff.create_ticket,
        name='submit'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/$',
        staff.view_ticket,
        name='view'),
    
    url(r'^user/tickets/(?P<ticket_id>[0-9]+)/$',
        views.view_ticket,
        name='userview'),

    
     url(r'^tickets/(?P<ticket_id>[0-9]+)/update/$',
        staff.update_ticket,
        name='update'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/followup_edit/(?P<followup_id>[0-9]+)/$',
        staff.followup_edit,
        name='followup_edit'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/followup_delete/(?P<followup_id>[0-9]+)/$',
        staff.followup_delete,
        name='followup_delete'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/edit/$',
        staff.edit_ticket,
        name='edit'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/update/$',
        staff.update_ticket,
        name='update'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/hold/$',
        staff.hold_ticket,
        name='hold'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/unhold/$',
        staff.unhold_ticket,
        name='unhold'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/cc/$',
        staff.ticket_cc,
        name='ticket_cc'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/cc/add/$',
        staff.ticket_cc_add,
        name='ticket_cc_add'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/cc/delete/(?P<cc_id>[0-9]+)/$',
        staff.ticket_cc_del,
        name='ticket_cc_del'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/dependency/add/$',
        staff.ticket_dependency_add,
        name='ticket_dependency_add'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/dependency/delete/(?P<dependency_id>[0-9]+)/$',
        staff.ticket_dependency_del,
        name='ticket_dependency_del'),

    url(r'^tickets/(?P<ticket_id>[0-9]+)/attachment_delete/(?P<attachment_id>[0-9]+)/$',
        staff.attachment_del,
        name='attachment_del'),

    url(r'^rss/$',
        staff.rss_list,
        name='rss_index'),
]

urlpatterns += [
        url(r'^kb/$',
            kb.index,
            name='kb_index'),

        url(r'^kb/(?P<item>[0-9]+)/$',
            kb.item,
            name='kb_item'),

        url(r'^kb/(?P<slug>[A-Za-z0-9_-]+)/$',
            kb.category,
            name='kb_category'),
    ]


urlpatterns += [
    path('login/', TokenObtainPairView.as_view(), name = 'token_pair'),
    path('refreshtoken/', TokenRefreshView.as_view(), name = 'refresh_token'),
    path('tokenverify/', TokenVerifyView.as_view(), name = 'token_verify'),
]

"""
- For the first view, you send the refresh token to get a new access token.
- For the second view, you send the client credentials (username and password)
  to get BOTH a new access and refresh token.
"""