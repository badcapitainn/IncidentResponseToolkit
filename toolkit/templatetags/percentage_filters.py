# toolkit/templatetags/percentage_filters.py
from django import template

register = template.Library()

@register.filter
def percentage(value, total):
    """Calculate percentage of value relative to total"""
    try:
        return f"{float(value) / float(total) * 100:.1f}%"
    except (ValueError, ZeroDivisionError):
        return "0%"