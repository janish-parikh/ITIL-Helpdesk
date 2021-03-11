from __future__ import unicode_literals

import json
import re
from datetime import date, datetime, timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.db.models import Q
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dates import MONTHS_3
from django.utils.html import escape
from django.utils.translation import ugettext as _
from rest_framework import status
from rest_framework.decorators import action, api_view, permission_classes,authentication_classes
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import (AllowAny, IsAdminUser, IsAuthenticated,
                                        IsAuthenticatedOrReadOnly)
from rest_framework.response import Response

from api import settings as helpdesk_settings

from .decorators import protect_view, staff_member_required, superuser_required
from .lib import (apply_query, process_attachments, queue_template_context,
                  safe_template_context, send_templated_mail)
from .models import (Attachment, FollowUp, PreSetReply, Queue, Ticket,
                     TicketCC, TicketChange, TicketDependency)
from .serializers import (CurrentUserSerializer, EditFollowUpSerializer,
                          EditTicketSerializer, EmailTemplateSerializer,
                          FollowUpSerializer, KBCategorySerializer,
                          KBItemSerializer, PreSetReplySerializer,
                          PublicTicketSerializer, QueueSerializer,
                          TicketCCEmailSerializer, TicketCCSerializer, 
                          TicketCCUserSerializer, TicketChangeSerializer,
                          TicketDependencySerializer, TicketFormSerializer,
                          TicketSerializer, UserSerializer, UserSettingsSerializer)

User = get_user_model()
from .serializers import UserSerializer
from rest_framework import viewsets
from rest_framework.response import Response

class Userlist(viewsets.ViewSet):
    """
    A simple ViewSet for listing or retrieving users.
    """
    # permission_classes=[IsAuthenticated]
    # authentication_classes=[JWTAuthentication]
    def list(self, request):
        if not request.user.is_staff:
            raise PermissionDenied
        queryset = User.objects.all()
        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data)


def _get_user_queues(user):
    """Return the list of Queues the user can access.
    :param user: The User (the class should have the has_perm method)
    :return: A Python list of Queues
    """
    all_queues = Queue.objects.all()
    limit_queues_by_user = \
        helpdesk_settings.HELPDESK_ENABLE_PER_QUEUE_STAFF_PERMISSION \
        and not user.is_superuser
    if limit_queues_by_user:
        id_list = [q.pk for q in all_queues if user.has_perm(q.permission_name)]
        return all_queues.filter(pk__in=id_list)
    else:
        return all_queues

def _has_access_to_queue(user, queue):
    """Check if a certain user can access a certain queue.
    :param user: The User (the class should have the has_perm method)
    :param queue: The django-helpdesk Queue instance
    :return: True if the user has permission (either by default or explicitly), false otherwise
    """
    if user.is_superuser or not user.is_staff:
        return True
    else:
        return user.has_perm(queue.permission_name)

def _is_my_ticket(user, ticket):
    """Check to see if the user has permission to access
    a ticket. If not then deny access."""
    if user.is_superuser or user.is_staff:
        return True
    elif ticket.assigned_to and user.id == ticket.assigned_to.id:
        return True
    else:
        return False

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def dashboard(request):
    """
    A quick summary overview for users: A list of their own tickets, a table
    showing ticket counts by queue/status, and a list of unassigned tickets
    with options for them to 'Take' ownership of said tickets.
    """

    # user settings num tickets per page
    tickets_per_page = 25

    # page vars for the three ticket tables
    user_tickets_page = request.GET.get(_('ut_page'), 1)
    user_tickets_closed_resolved_page = request.GET.get(_('utcr_page'), 1)
    all_tickets_reported_by_current_user_page = request.GET.get(_('atrbcu_page'), 1)

    # open & reopened tickets, assigned to current user
    tickets = Ticket.objects.select_related('queue').filter(
        assigned_to=request.user.id,
    ).exclude(
        status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS],
    )

    # closed & resolved tickets, assigned to current user
    tickets_closed_resolved = Ticket.objects.select_related('queue').filter(
        assigned_to=request.user.id,
        status__in=[Ticket.CLOSED_STATUS, Ticket.RESOLVED_STATUS])

    user_queues = _get_user_queues(request.user)

    unassigned_tickets = Ticket.objects.select_related('queue').filter(
        assigned_to__isnull=True,
        queue__in=user_queues
    ).exclude(
        status=Ticket.CLOSED_STATUS,
    )

    # all tickets, reported by current user
    all_tickets_reported_by_current_user = ''
    email_current_user = request.user.email
    if email_current_user:
        all_tickets_reported_by_current_user = Ticket.objects.select_related('queue').filter(
            submitter_email=email_current_user,
        ).order_by('status')

    tickets_in_queues = Ticket.objects.filter(
        queue__in=user_queues,
    )
    basic_ticket_stats = calc_basic_ticket_stats(tickets_in_queues)

    # The following query builds a grid of queues & ticket statuses,
    # to be displayed to the user. EG:
    #          Open  Resolved
    # Queue 1    10     4
    # Queue 2     4    12

    queues = _get_user_queues(request.user).values_list('id', flat=True)

    from_clause = """FROM    helpdesk_ticket t,
                    helpdesk_queue q"""
    if queues:
        where_clause = """WHERE   q.id = t.queue_id AND
                        q.id IN (%s)""" % (",".join(("%d" % pk for pk in queues)))
    else:
        where_clause = """WHERE   q.id = t.queue_id"""

    # # get user assigned tickets page
    # paginator = Paginator(
    #     tickets, tickets_per_page)
    # try:
    #     tickets = paginator.page(user_tickets_page)
    # except PageNotAnInteger:
    #     tickets = paginator.page(1)
    # except EmptyPage:
    #     tickets = paginator.page(
    #         paginator.num_pages)

    # # get user completed tickets page
    # paginator = Paginator(
    #     tickets_closed_resolved, tickets_per_page)
    # try:
    #     tickets_closed_resolved = paginator.page(
    #         user_tickets_closed_resolved_page)
    # except PageNotAnInteger:
    #     tickets_closed_resolved = paginator.page(1)
    # except EmptyPage:
    #     tickets_closed_resolved = paginator.page(
    #         paginator.num_pages)

    # # get user submitted tickets page
    # paginator = Paginator(
    #     all_tickets_reported_by_current_user, tickets_per_page)
    # try:
    #     all_tickets_reported_by_current_user = paginator.page(
    #         all_tickets_reported_by_current_user_page)
    # except PageNotAnInteger:
    #     all_tickets_reported_by_current_user = paginator.page(1)
    # except EmptyPage:
    #     all_tickets_reported_by_current_user = paginator.page(
    #         paginator.num_pages)

    user_tickets_serialier=TicketSerializer(tickets, many = True)
    user_tickets_closed_resolved_serializer = TicketSerializer(tickets_closed_resolved, many = True)
    unassigned_tickets_serializer = TicketSerializer(unassigned_tickets, many = True)
    all_tickets_reported_by_current_user_serializer = TicketSerializer(all_tickets_reported_by_current_user, many = True)
    
    if request.user.is_active and request.user.is_staff and request.user.is_authenticated:
        return Response({
            'user_tickets': user_tickets_serialier.data,
            'user_tickets_closed_resolved': user_tickets_closed_resolved_serializer.data,
            'unassigned_tickets': unassigned_tickets_serializer.data,
            'all_tickets_reported_by_current_user': all_tickets_reported_by_current_user_serializer.data,
            'basic_ticket_stats': basic_ticket_stats,

        })
    
    elif request.user.is_active and request.user.is_authenticated:         
        return Response({
            'all_tickets_reported_by_current_user': all_tickets_reported_by_current_user_serializer.data,
            })
    else:
        raise PermissionDenied

def days_since_created(today, ticket):
    return (today - ticket.created).days

def date_rel_to_today(today, offset):
    return today - timedelta(days=offset)

def sort_string(begin, end):
    return 'sort=created&date_from=%s&date_to=%s&status=%s&status=%s&status=%s' % (
        begin, end, Ticket.OPEN_STATUS, Ticket.REOPENED_STATUS, Ticket.RESOLVED_STATUS)

def calc_average_nbr_days_until_ticket_resolved(Tickets):
    nbr_closed_tickets = len(Tickets)
    days_per_ticket = 0
    days_each_ticket = list()

    for ticket in Tickets:
        time_ticket_open = ticket.modified - ticket.created
        days_this_ticket = time_ticket_open.days
        days_per_ticket += days_this_ticket
        days_each_ticket.append(days_this_ticket)

    if nbr_closed_tickets > 0:
        mean_per_ticket = days_per_ticket / nbr_closed_tickets
    else:
        mean_per_ticket = 0

    return mean_per_ticket

def calc_basic_ticket_stats(Tickets):

    # all not closed tickets (open, reopened, resolved,) - independent of user
    all_open_tickets = Tickets.exclude(status=Ticket.CLOSED_STATUS)
    today = datetime.today()

    date_30 = date_rel_to_today(today, 30)
    date_60 = date_rel_to_today(today, 60)
    date_30_str = date_30.strftime('%Y-%m-%d')
    date_60_str = date_60.strftime('%Y-%m-%d')

    # > 0 & <= 30
    ota_le_30 = all_open_tickets.filter(created__gte=date_30_str)
    N_ota_le_30 = len(ota_le_30)

    # >= 30 & <= 60
    ota_le_60_ge_30 = all_open_tickets.filter(created__gte=date_60_str, created__lte=date_30_str)
    N_ota_le_60_ge_30 = len(ota_le_60_ge_30)

    # >= 60
    ota_ge_60 = all_open_tickets.filter(created__lte=date_60_str)
    N_ota_ge_60 = len(ota_ge_60)

    # (O)pen (T)icket (S)tats
    ots = list()
    # label, number entries, color, sort_string
    ots.append(['Tickets < 30 days', N_ota_le_30, 'success',
                sort_string(date_30_str, ''), ])
    ots.append(['Tickets 30 - 60 days', N_ota_le_60_ge_30,
                'success' if N_ota_le_60_ge_30 == 0 else 'warning',
                sort_string(date_60_str, date_30_str), ])
    ots.append(['Tickets > 60 days', N_ota_ge_60,
                'success' if N_ota_ge_60 == 0 else 'danger',
                sort_string('', date_60_str), ])

    # all closed tickets - independent of user.
    all_closed_tickets = Tickets.filter(status=Ticket.CLOSED_STATUS)
    average_nbr_days_until_ticket_closed = \
        calc_average_nbr_days_until_ticket_resolved(all_closed_tickets)
    # all closed tickets that were opened in the last 60 days.
    all_closed_last_60_days = all_closed_tickets.filter(created__gte=date_60_str)
    average_nbr_days_until_ticket_closed_last_60_days = \
        calc_average_nbr_days_until_ticket_resolved(all_closed_last_60_days)

    # put together basic stats
    basic_ticket_stats = {
        'average_nbr_days_until_ticket_closed': average_nbr_days_until_ticket_closed,
        'average_nbr_days_until_ticket_closed_last_60_days':
            average_nbr_days_until_ticket_closed_last_60_days,
        'open_ticket_stats': ots,
    }
    return basic_ticket_stats

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def ticket_list(request):
    if not request.user.is_staff:
        raise PermissionDenied()
    context = {}
    user_queues = _get_user_queues(request.user)
    # Prefilter the allowed tickets
    base_tickets = Ticket.objects.filter(queue__in=user_queues)
    # Query_params will hold a dictionary of parameters relating to
    # a query, to be saved if needed:
    query_params = {
        'filtering': {},
        'sorting': None,
        'sortreverse': False,
        'keyword': None,
        'search_string': None,
    }

    # If the user is coming from the header/navigation search box, lets' first
    # look at their query to see if they have entered a valid ticket number. If
    # they have, just redirect to that ticket number. Otherwise, we treat it as
    # a keyword search.

    if request.GET.get('search_type', None) == 'header':
        query = request.GET.get('q')
        filter = None
        if query.find('-') > 0:
            try:
                queue, id = Ticket.queue_and_id_from_query(query)
                id = int(id)
            except ValueError:
                id = None

            if id:
                filter = {'queue__slug': queue, 'id': id}
        else:
            try:
                query = int(query)
            except ValueError:
                query = None

            if query:
                filter = {'id': int(query)}

        if filter:
            try:
                ticket = base_tickets.get(**filter)
                return HttpResponseRedirect(ticket.staff_url)
            except Ticket.DoesNotExist:
                # Go on to standard keyword searching
                pass

    elif not ('queue' in request.GET or
              'assigned_to' in request.GET or
              'status' in request.GET or
              'q' in request.GET or
              'sort' in request.GET or
              'sortreverse' in request.GET):

        # Fall-back if no querying is being done, force the list to only
        # show open/reopened/resolved (not closed) cases sorted by creation
        # date.

        query_params = {
            'filtering': {'status__in': [1, 2, 3]},
            'sorting': 'created',
        }
    else:
        queues = request.GET.getlist('queue')
        if queues:
            try:
                queues = [int(q) for q in queues]
                query_params['filtering']['queue__id__in'] = queues
            except ValueError:
                pass

        owners = request.GET.getlist('assigned_to')
        if owners:
            try:
                owners = [int(u) for u in owners]
                query_params['filtering']['assigned_to__id__in'] = owners
            except ValueError:
                pass

        statuses = request.GET.getlist('status')
        if statuses:
            try:
                statuses = [int(s) for s in statuses]
                query_params['filtering']['status__in'] = statuses
            except ValueError:
                pass

        date_from = request.GET.get('date_from')
        if date_from:
            query_params['filtering']['created__gte'] = date_from

        date_to = request.GET.get('date_to')
        if date_to:
            query_params['filtering']['created__lte'] = date_to


        # SORTING
        sort = request.GET.get('sort', None)
        if sort not in ('status', 'assigned_to', 'created', 'title', 'queue', 'priority'):
            sort = 'created'
        query_params['sorting'] = sort

        sortreverse = request.GET.get('sortreverse', None)
        query_params['sortreverse'] = sortreverse

    tickets = base_tickets.select_related()

    try:
        ticket_qs = apply_query(tickets, query_params)
    except ValidationError:
        # invalid parameters in query, return default query
        query_params = {
            'filtering': {'status__in': [1, 2, 3]},
            'sorting': 'created',
        }
        ticket_qs = apply_query(tickets, query_params)
    
    
    tickets=TicketSerializer(ticket_qs,many=True)
    user_choices=User.objects.filter(is_active=True, is_staff=True)
    User_choices = CurrentUserSerializer(user_choices, many = True)
    queue_choices=user_queues
    queue_choices= QueueSerializer(queue_choices, many = True)
    return Response({
        "tickets": tickets.data,
        "user_choices": User_choices.data,
        "queue_choices": queue_choices.data,
        "status_choices":Ticket.STATUS_CHOICES,
        "query_params":query_params
    })

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def view_ticket(request, ticket_id):
    if not request.user.is_staff:
        raise PermissionDenied()
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()
    if 'take' in request.GET:
        # Allow the user to assign the ticket to themselves whilst viewing it.

        # Trick the update_ticket() view into thinking it's being called with
        # a valid POST.
        request.POST = {
            'owner': request.user.id,
            'public': 1,
            'title': ticket.title,
            'comment': ''
        }
        return update_ticket(request, ticket_id)

    if 'close' in request.GET and ticket.status == Ticket.RESOLVED_STATUS:
        if not ticket.assigned_to:
            owner = 0
        else:
            owner = ticket.assigned_to.id

        # Trick the update_ticket() view into thinking it's being called with
        # a valid POST.
        request.POST = {
            'new_status': Ticket.CLOSED_STATUS,
            'public': 1,
            'owner': owner,
            'title': ticket.title,
            'comment': _('Accepted resolution and closed ticket'),
        }

        return update_ticket(request, ticket_id)

    users = User.objects.filter(is_active=True, is_staff=True).order_by(User.USERNAME_FIELD)
    folloups = FollowUp.objects.filter(ticket_id = ticket_id)
    users_serializer = CurrentUserSerializer(users, many=True)
    # TODO: shouldn't this template get a form to begin with?
    serializer = TicketFormSerializer()
    ticket_serializer = TicketSerializer(ticket)
    folloups_serializer = FollowUpSerializer(folloups, many = True)
    ticketcc_string, show_subscribe = \
        return_ticketccstring_and_show_subscribe(request.user, ticket)

    return Response( {
        'ticket': ticket_serializer.data,
        'followups' : folloups_serializer.data,
        'active_users': users_serializer.data,
        'priorities': Ticket.PRIORITY_CHOICES,
        'preset_replies': PreSetReply.objects.filter(Q(queues=ticket.queue) | Q(queues__isnull=True)),
        'ticketcc_string': ticketcc_string,
        'SHOW_SUBSCRIBE': show_subscribe,
    })


def return_ticketccstring_and_show_subscribe(user, ticket):
    """used in view_ticket() and followup_edit()"""
    # create the ticketcc_string and check whether current user is already
    # subscribed
    username = user.get_username().upper()
    useremail = user.email.upper()
    strings_to_check = list()
    strings_to_check.append(username)
    strings_to_check.append(useremail)

    ticketcc_string = '' 
    all_ticketcc = ticket.ticketcc_set.all()
    counter_all_ticketcc = len(all_ticketcc) - 1
    show_subscribe = True
    for i, ticketcc in enumerate(all_ticketcc):
        ticketcc_this_entry = str(ticketcc.display)
        ticketcc_string += ticketcc_this_entry
        if i < counter_all_ticketcc:
            ticketcc_string += ', '
        if strings_to_check.__contains__(ticketcc_this_entry.upper()):
            show_subscribe = False

    # check whether current user is a submitter or assigned to ticket
    assignedto_username = str(ticket.assigned_to).upper()
    strings_to_check = list()
    if ticket.submitter_email is not None:
        submitter_email = ticket.submitter_email.upper()
        strings_to_check.append(submitter_email)
    strings_to_check.append(assignedto_username)
    if strings_to_check.__contains__(username) or strings_to_check.__contains__(useremail):
        show_subscribe = False

    return ticketcc_string, show_subscribe


def subscribe_staff_member_to_ticket(ticket, user):
    """used in view_ticket() and update_ticket()"""
    ticketcc = TicketCC(
        ticket=ticket,
        user=user,
        can_view=True,
        can_update=True,
    )
    ticketcc.save()


# @api_view(['GET', 'POST'])
# @authentication_classes([JWTAuthentication])
# @staff_member_required
# def update_ticket(request, ticket_id, public=False):
#     if not (public or (
#             request.user.is_authenticated and
#             request.user.is_active and
#             request.user.is_staff)):
#         raise PermissionDenied

#     ticket = get_object_or_404(Ticket, id=ticket_id)

#     date_re = re.compile(
#         r'(?P<month>\d{1,2})/(?P<day>\d{1,2})/(?P<year>\d{4})$'
#     )

#     comment = request.POST.get('comment', '')
#     new_status = int(request.POST.get('new_status', ticket.status))
#     title = request.POST.get('title', '')
#     public = request.POST.get('public', False)
#     owner = int(request.POST.get('owner', -1))
#     priority = int(request.POST.get('priority', ticket.priority))
#     due_date_year = int(request.POST.get('due_date_year', 0))
#     due_date_month = int(request.POST.get('due_date_month', 0))
#     due_date_day = int(request.POST.get('due_date_day', 0))
#     # NOTE: jQuery's default for dates is mm/dd/yy
#     # very US-centric but for now that's the only format supported
#     # until we clean up code to internationalize a little more
#     due_date = request.POST.get('due_date', None) or None

#     if due_date is not None:
#         # based on Django code to parse dates:
#         # https://docs.djangoproject.com/en/2.0/_modules/django/utils/dateparse/
#         match = date_re.match(due_date)
#         if match:
#             kw = {k: int(v) for k, v in match.groupdict().items()}
#             due_date = date(**kw)
#     else:
#         # old way, probably deprecated?
#         if not (due_date_year and due_date_month and due_date_day):
#             due_date = ticket.due_date
#         else:
#             # NOTE: must be an easier way to create a new date than doing it this way?
#             if ticket.due_date:
#                 due_date = ticket.due_date
#             else:
#                 due_date = timezone.now()
#             due_date = due_date.replace(due_date_year, due_date_month, due_date_day)

#     no_changes = all([
#         not request.FILES,
#         not comment,
#         new_status == ticket.status,
#         title == ticket.title,
#         priority == int(ticket.priority),
#         due_date == ticket.due_date,
#         (owner == -1) or (not owner and not ticket.assigned_to) or
#         (owner and User.objects.get(id=owner) == ticket.assigned_to),
#     ])
#     if no_changes:
#         return Response("NO changes")

#     # We need to allow the 'ticket' and 'queue' contexts to be applied to the
#     # comment.
#     context = safe_template_context(ticket)

#     from django.template import engines
#     template_func = engines['django'].from_string
#     # this prevents system from trying to render any template tags
#     # broken into two stages to prevent changes from first replace being themselves
#     # changed by the second replace due to conflicting syntax
#     comment = comment.replace('{%', 'X-HELPDESK-COMMENT-VERBATIM').replace('%}', 'X-HELPDESK-COMMENT-ENDVERBATIM')
#     comment = comment.replace('X-HELPDESK-COMMENT-VERBATIM', '{% verbatim %}{%').replace(
#         'X-HELPDESK-COMMENT-ENDVERBATIM', '%}{% endverbatim %}')
#     # render the neutralized template
#     comment = template_func(comment).render(context)

#     if owner is -1 and ticket.assigned_to:
#         owner = ticket.assigned_to.id

#     f = FollowUp(ticket=ticket, date=timezone.now(), comment=comment)

#     if request.user.is_staff or helpdesk_settings.HELPDESK_ALLOW_NON_STAFF_TICKET_UPDATE:
#         f.user = request.user

#     f.public = public

#     reassigned = False

#     old_owner = ticket.assigned_to
#     if owner != -1:
#         if owner != 0 and ((ticket.assigned_to and owner != ticket.assigned_to.id) or not ticket.assigned_to):
#             new_user = User.objects.get(id=owner)
#             f.title = _('Assigned to %(username)s') % {
#                 'username': new_user.get_username(),
#             }
#             ticket.assigned_to = new_user
#             reassigned = True
#         # user changed owner to 'unassign'
#         elif owner == 0 and ticket.assigned_to is not None:
#             f.title = _('Unassigned')
#             ticket.assigned_to = None

#     old_status_str = ticket.get_status_display()
#     old_status = ticket.status
#     if new_status != ticket.status:
#         ticket.status = new_status
#         ticket.save()
#         f.new_status = new_status
#         ticket_status_changed = True
#         if f.title:
#             f.title += ' and %s' % ticket.get_status_display()
#         else:
#             f.title = '%s' % ticket.get_status_display()

#     if not f.title:
#         if f.comment:
#             f.title = _('Comment')
#         else:
#             f.title = _('Updated')

#     f.save()

#     files = process_attachments(f, request.FILES.getlist('attachment'))

#     if title and title != ticket.title:
#         c = TicketChange(
#             followup=f,
#             field=_('Title'),
#             old_value=ticket.title,
#             new_value=title,
#         )
#         c.save()
#         ticket.title = title

#     if new_status != old_status:
#         c = TicketChange(
#             followup=f,
#             field=_('Status'),
#             old_value=old_status_str,
#             new_value=ticket.get_status_display(),
#         )
#         c.save()

#     if ticket.assigned_to != old_owner:
#         c = TicketChange(
#             followup=f,
#             field=_('Owner'),
#             old_value=old_owner,
#             new_value=ticket.assigned_to,
#         )
#         c.save()

#     if priority != ticket.priority:
#         c = TicketChange(
#             followup=f,
#             field=_('Priority'),
#             old_value=ticket.priority,
#             new_value=priority,
#         )
#         c.save()
#         ticket.priority = priority

#     if due_date != ticket.due_date:
#         c = TicketChange(
#             followup=f,
#             field=_('Due on'),
#             old_value=ticket.due_date,
#             new_value=due_date,
#         )
#         c.save()
#         ticket.due_date = due_date

#     if new_status in (Ticket.RESOLVED_STATUS, Ticket.CLOSED_STATUS):
#         if new_status == Ticket.RESOLVED_STATUS or ticket.resolution is None:
#             ticket.resolution = comment

#     messages_sent_to = []

#     # ticket might have changed above, so we re-instantiate context with the
#     # (possibly) updated ticket.
#     context = safe_template_context(ticket)
#     context.update(
#         resolution=ticket.resolution,
#         comment=f.comment,
#     )

#     if public and (f.comment or (
#             f.new_status in (Ticket.RESOLVED_STATUS,
#                              Ticket.CLOSED_STATUS))):
#         if f.new_status == Ticket.RESOLVED_STATUS:
#             template = 'resolved_'
#         elif f.new_status == Ticket.CLOSED_STATUS:
#             template = 'closed_'
#         else:
#             template = 'updated_'

#         template_suffix = 'submitter'

#         if ticket.submitter_email:
#             send_templated_mail(
#                 template + template_suffix,
#                 context,
#                 recipients=ticket.submitter_email,
#                 sender=ticket.queue.from_address,
#                 fail_silently=True,
#                 files=files,
#             )
#             messages_sent_to.append(ticket.submitter_email)

#         template_suffix = 'cc'

#         for cc in ticket.ticketcc_set.all():
#             if cc.email_address not in messages_sent_to:
#                 send_templated_mail(
#                     template + template_suffix,
#                     context,
#                     recipients=cc.email_address,
#                     sender=ticket.queue.from_address,
#                     fail_silently=True,
#                     files=files,
#                 )
#                 messages_sent_to.append(cc.email_address)

#     if ticket.assigned_to and \
#             request.user != ticket.assigned_to and \
#             ticket.assigned_to.email and \
#             ticket.assigned_to.email not in messages_sent_to:
#         # We only send e-mails to staff members if the ticket is updated by
#         # another user. The actual template varies, depending on what has been
#         # changed.
#         if reassigned:
#             template_staff = 'assigned_owner'
#         elif f.new_status == Ticket.RESOLVED_STATUS:
#             template_staff = 'resolved_owner'
#         elif f.new_status == Ticket.CLOSED_STATUS:
#             template_staff = 'closed_owner'
#         else:
#             template_staff = 'updated_owner'

#         if (not reassigned or
#             (reassigned and
#              ticket.assigned_to.usersettings_helpdesk.settings.get(
#                  'email_on_ticket_assign', False))) or \
#                 (not reassigned and
#                  ticket.assigned_to.usersettings_helpdesk.settings.get(
#                      'email_on_ticket_change', False)):
#             send_templated_mail(
#                 template_staff,
#                 context,
#                 recipients=ticket.assigned_to.email,
#                 sender=ticket.queue.from_address,
#                 fail_silently=True,
#                 files=files,
#             )
#             messages_sent_to.append(ticket.assigned_to.email)

#     if ticket.queue.updated_ticket_cc and ticket.queue.updated_ticket_cc not in messages_sent_to:
#         if reassigned:
#             template_cc = 'assigned_cc'
#         elif f.new_status == Ticket.RESOLVED_STATUS:
#             template_cc = 'resolved_cc'
#         elif f.new_status == Ticket.CLOSED_STATUS:
#             template_cc = 'closed_cc'
#         else:
#             template_cc = 'updated_cc'

#         send_templated_mail(
#             template_cc,
#             context,
#             recipients=ticket.queue.updated_ticket_cc,
#             sender=ticket.queue.from_address,
#             fail_silently=True,
#             files=files,
#         )

#     ticket.save()

#     # auto subscribe user if enabled
#     if helpdesk_settings.HELPDESK_AUTO_SUBSCRIBE_ON_TICKET_RESPONSE and request.user.is_authenticated:
#         ticketcc_string, SHOW_SUBSCRIBE = return_ticketccstring_and_show_subscribe(request.user, ticket)
#         if SHOW_SUBSCRIBE:
#             subscribe_staff_member_to_ticket(ticket, request.user)
#     return Response("Helpdesk Redirect")
#     # return return_to_ticket(request.user, helpdesk_settings, ticket)


def return_to_ticket(user, helpdesk_settings, ticket):
    """Helper function for update_ticket"""

    if user.is_staff or helpdesk_settings.HELPDESK_ALLOW_NON_STAFF_TICKET_UPDATE:
        return HttpResponseRedirect(ticket.get_absolute_url())
    else:
        return HttpResponseRedirect(ticket.ticket_url)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def rss_list(request):
    queues = Queue.objects.all()
    serializer = QueueSerializer(queues, many = True)
    return Response(serializer.data)

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def edit_ticket(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    if request.method == 'POST':
        serializer = EditTicketSerializer(data = request.data, instance = ticket)
        if serializer.is_valid():
            ticket = serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)   
    else:
        serializer = EditTicketSerializer(instance=ticket)
    return Response(serializer.data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def create_ticket(request):
    assignable_users = User.objects.filter(is_active=True, is_staff=True).order_by(User.USERNAME_FIELD)
    if request.method == 'POST':
        serializer = TicketFormSerializer(data=request.data)
        serializer.fields['queue'].choices = [('', '--------')] + [
            (q.id, q.title) for q in Queue.objects.all()]
        serializer.fields['assigned_to'].choices = [('', '--------')] + [
            (u.id, u.get_username()) for u in assignable_users]
        if serializer.is_valid():
            ticket = serializer.save(user=request.user)
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)   
    else:
        initial_data = {}
        initial_data['submitter_email'] = request.GET['submitter_email']
        if 'queue' in request.GET:
            initial_data['queue'] = request.GET['queue']

        serializer = TicketFormSerializer(initial=initial_data)
        serializer.fields['queue'].choices = [('', '--------')] + [
            (q.id, q.title) for q in Queue.objects.all()]
        serializer.fields['assigned_to'].choices = [('', '--------')] + [
            (u.id, u.get_username()) for u in assignable_users]
    return Response(serializer.data)

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def hold_ticket(request, ticket_id, unhold=False):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    if unhold:
        ticket.on_hold = False
        title = _('Ticket taken off hold')
    else:
        ticket.on_hold = True
        title = _('Ticket placed on hold')

    f = FollowUp(
        ticket=ticket,
        user=request.user,
        title=title,
        date=timezone.now(),
        public=True,
    )
    f.save()

    ticket.save()
    ticket_serializer = TicketSerializer(ticket)
    return Response(ticket_serializer.data)

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def unhold_ticket(request, ticket_id, unhold = True):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    if unhold:
        ticket.on_hold = False
        title = _('Ticket taken off hold')
    else:
        ticket.on_hold = True
        title = _('Ticket placed on hold')

    f = FollowUp(
        ticket=ticket,
        user=request.user,
        title=title,
        date=timezone.now(),
        public=True,
        )
    f.save()

    ticket.save()
    ticket_serializer = TicketSerializer(ticket)
    return Response(ticket_serializer.data)

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def ticket_cc(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    ticket_serializer = TicketSerializer(ticket)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    copies_to = ticket.ticketcc_set.all()
    serializer = TicketCCSerializer(copies_to, many=True)

    return Response({'copies_to': serializer.data,
        'ticket': ticket_serializer.data, })

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def ticket_cc_add(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    ticket_serializer = TicketSerializer(ticket)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    if request.method == 'POST':
        serializer = TicketCCSerializer(data = request.data)
        if serializer.is_valid():
           serializer.save()
           return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

    else:
        serializer_email = TicketCCEmailSerializer()
        serializer_user = TicketCCUserSerializer()
    return Response({'ticket': ticket_serializer.data,
        'email': serializer_email.data,
        'user': serializer_user.data,})

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def ticket_cc_del(request, ticket_id, cc_id):
    cc = get_object_or_404(TicketCC, ticket__id=ticket_id, id=cc_id)
    serializer = TicketCCSerializer(cc)
    if request.method == 'POST':
        cc.delete()
    return Response(serializer.data)

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def followup_edit(request, ticket_id, followup_id):
    """Edit followup options with an ability to change the ticket."""
    followup = get_object_or_404(FollowUp, id=followup_id)
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    if request.method == 'GET':
        serializer = EditFollowUpSerializer(initial={
            'title': escape(followup.title),
            'ticket': followup.ticket,
            'comment': escape(followup.comment),
            'public': followup.public,
            'new_status': followup.new_status,
        })

        ticketcc_string, show_subscribe = \
            return_ticketccstring_and_show_subscribe(request.user, ticket)

        followup_serialier=FollowUpSerializer(followup)
        ticket_serializer = TicketSerializer(ticket)
        return Response({
            'followup': followup_serialier.data,
            'ticket': ticket_serializer.data,
            'serializer': serializer.data,
            'ticketcc_string': ticketcc_string,
        })

    elif request.method == 'POST':
        serializer = EditFollowUpSerializer(data=request.data)
        if serializer.is_valid():
            title = serializer.validated_data['title']
            _ticket = serializer.validated_data['ticket']
            comment = serializer.validated_data['comment']
            public = serializer.validated_data['public']
            new_status = serializer.validated_data['new_status']
            # will save previous date
            old_date = followup.date
            new_followup = FollowUp(title=title, date=old_date, ticket=_ticket, comment=comment, public=public,
                                    new_status=new_status, )
            # keep old user if one did exist before.
            if followup.user:
                new_followup.user = followup.user
            new_followup.save()
            # get list of old attachments & link them to new_followup
            attachments = Attachment.objects.filter(followup=followup)
            for attachment in attachments:
                attachment.followup = new_followup
                attachment.save()
            # delete old followup
            followup.delete()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def followup_delete(request, ticket_id, followup_id):
    """followup delete for superuser"""

    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not request.user.is_superuser:
        raise PermissionDenied
    followup = get_object_or_404(FollowUp, id=followup_id)
    serializer = FollowUpSerializer(followup)
    followup.delete()
    return Response(serializer.data)

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def ticket_dependency_add(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()

    serializer = TicketDependencySerializer(data = request.data)
    # A ticket cannot depends on itself or on a ticket already depending on it
    serializer.fields['depends_on'].queryset = Ticket.objects.exclude(
        Q(id=ticket.id) | Q(ticketdependency__depends_on=ticket)
    )
    if serializer.is_valid():   
        ticketdependency = serializer.save(ticket_id=ticket.id)
        # ticketdependency.ticket = ticket
        # ticketdependency.save()
        # ticket_serializer = TicketSerializer(ticket)
        return Response(serializer.data)
       # ticket_serializer.data})
    # return Response({serializer.errors, ticket_serializer.errors})
    return Response(serializer.errors)

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def ticket_dependency_del(request, ticket_id, dependency_id):
    dependency = get_object_or_404(TicketDependency, ticket__id=ticket_id, id=dependency_id)
    serializer = TicketDependencySerializer(dependency, many= True)
    if request.method == 'POST':
        dependency.delete()
    return Response(serializer.data)

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@staff_member_required
def attachment_del(request, ticket_id, attachment_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if not _has_access_to_queue(request.user, ticket.queue):
        raise PermissionDenied()
    if not _is_my_ticket(request.user, ticket):
        raise PermissionDenied()
    attachment = get_object_or_404(Attachment, id=attachment_id)
    serializer = AttachmentSerializer(attachment)
    if request.method == 'POST':
        attachment.delete()
    return Response({'attachment': serializer.data}, status=204)
