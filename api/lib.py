import logging
import mimetypes
import os
from base64 import decodebytes as b64decode
from base64 import encodebytes as b64encode
from smtplib import SMTPException

from django.conf import settings
from django.db.models import Q
from django.utils import six
from django.utils.encoding import smart_text
from django.utils.safestring import mark_safe

from .models import Attachment, EmailTemplate

logger = logging.getLogger('helpdesk')

def send_templated_mail(
                        context,
                        recipients,
                        sender=None,
                        bcc=None,
                        fail_silently=False,
                        files=None):
    """
    send_templated_mail() is a wrapper around Django's e-mail routines that
    allows us to easily send multipart (text/plain & text/html) e-mails using
    templates that are stored in the database. This lets the admin provide
    both a text and a HTML template for each message.
    template_name is the slug of the template to use for this message (see
        models.EmailTemplate)
    context is a dictionary to be used when rendering the template
    recipients can be either a string, eg 'a@b.com', or a list of strings.
    sender should contain a string, eg 'My Site <me@z.com>'. If you leave it
        blank, it'll use settings.DEFAULT_FROM_EMAIL as a fallback.
    bcc is an optional list of addresses that will receive this message as a
        blind carbon copy.
    fail_silently is passed to Django's mail routine. Set to 'True' to ignore
        any errors at send time.
    files can be a list of tuples. Each tuple should be a filename to attach,
        along with the File objects to be read. files can be blank.
    """
    from django.core.mail import EmailMultiAlternatives
    
    # keep new lines in html emails
    if 'comment' in context:
        context['comment'] = mark_safe(context['comment'].replace('\r\n', '<br>'))
 

    if isinstance(recipients, str):
        if recipients.find(','):
            recipients = recipients.split(',')
    elif type(recipients) != list:
        recipients = [recipients]

    msg = EmailMultiAlternatives(
                                 sender or settings.DEFAULT_FROM_EMAIL,
                                 recipients, bcc=bcc)

    if files:
        for filename, filefield in files:
            content = filefield.read()
            msg.attach(filename, content)

    logger.debug('Sending email to: {!r}'.format(recipients))

    try:
        return msg.send()
    except SMTPException as e:
        logger.exception('SMTPException raised while sending email to {}'.format(recipients))
        if not fail_silently:
            raise e
        return 0


def query_to_dict(results, descriptions):
    """
    Replacement method for cursor.dictfetchall() as that method no longer
    exists in psycopg2, and I'm guessing in other backends too.
    Converts the results of a raw SQL query into a list of dictionaries, suitable
    for use in templates etc.
    """

    output = []
    for data in results:
        row = {}
        i = 0
        for column in descriptions:
            row[column[0]] = data[i]
            i += 1

        output.append(row)
    return output


def apply_query(queryset, params):
    """
    Apply a dict-based set of filters & parameters to a queryset.
    queryset is a Django queryset, eg MyModel.objects.all() or
             MyModel.objects.filter(user=request.user)
    params is a dictionary that contains the following:
        filtering: A dict of Django ORM filters, eg:
            {'user__id__in': [1, 3, 103], 'title__contains': 'foo'}
        search_string: A freetext search string
        sorting: The name of the column to sort by
    """
    for key in params['filtering'].keys():
        filter = {key: params['filtering'][key]}
        queryset = queryset.filter(**filter)

    search = params.get('search_string', None)
    if search:
        qset = (
            Q(title__icontains=search) |
            Q(description__icontains=search) |
            Q(resolution__icontains=search) |
            Q(submitter_email__icontains=search) |
            Q(ticketcustomfieldvalue__value__icontains=search)
        )

        # Distinct works, when there are multiple custom fields
        queryset = queryset.filter(qset).distinct()

    sorting = params.get('sorting', None)
    if sorting:
        sortreverse = params.get('sortreverse', None)
        if sortreverse:
            sorting = "-%s" % sorting
        queryset = queryset.order_by(sorting)

    return queryset


def ticket_template_context(ticket):
    context = {}

    for field in ('title', 'created', 'modified', 'submitter_email',
                  'status', 'get_status_display', 'on_hold', 'description',
                  'resolution', 'priority', 'get_priority_display',
                  'last_escalation', 'ticket', 'ticket_for_url',
                  'get_status', 'ticket_url', 'staff_url', '_get_assigned_to'
                  ):
        attr = getattr(ticket, field, None)
        if callable(attr):
            context[field] = '%s' % attr()
        else:
            context[field] = attr
    context['assigned_to'] = context['_get_assigned_to']

    return context


def queue_template_context(queue):
    context = {}

    for field in ('title', 'slug', 'email_address', 'from_address'):
        attr = getattr(queue, field, None)
        if callable(attr):
            context[field] = attr()
        else:
            context[field] = attr

    return context


def safe_template_context(ticket):
    """
    Return a dictionary that can be used as a template context to render
    comments and other details with ticket or queue parameters. Note that
    we don't just provide the Ticket & Queue objects to the template as
    they could reveal confidential information. Just imagine these two options:
        * {{ ticket.queue.email_box_password }}
        * {{ ticket.assigned_to.password }}
    Ouch!
    The downside to this is that if we make changes to the model, we will also
    have to update this code. Perhaps we can find a better way in the future.
    """

    context = {
        'queue': queue_template_context(ticket.queue),
        'ticket': ticket_template_context(ticket),
    }
    context['ticket']['queue'] = context['queue']

    return context


def process_attachments(followup, attached_files):
    max_email_attachment_size = getattr(settings, 'HELPDESK_MAX_EMAIL_ATTACHMENT_SIZE', 512000)
    attachments = []

    for attached in attached_files:
        if attached.size:
            filename = smart_text(attached.name)
            att = Attachment(
                followup=followup,
                file=attached,
                filename=filename,
                mime_type=attached.content_type or
                mimetypes.guess_type(filename, strict=False)[0] or
                'application/octet-stream',
                size=attached.size,
            )
            att.save()

            if attached.size < max_email_attachment_size:
                # Only files smaller than 512kb (or as defined in
                # settings.HELPDESK_MAX_EMAIL_ATTACHMENT_SIZE) are sent via email.
                attachments.append([filename, att.file])

    return attachments
