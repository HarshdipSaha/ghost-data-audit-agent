import re
from dataclasses import dataclass,field
from .models import timestamp,UnresolvedAudit


def normalize(value):
    value=str(value or '').strip().casefold()
    if re.fullmatch(r'[+\d ()-]{7,}',value): return re.sub(r'\D','',value)
    return value


@dataclass
class Subject:
    user_id: str
    aliases: set
    current: dict
    alias_provenance: dict = field(default_factory=dict)
    cutoff: str = ''


class IdentityResolver:
    def __init__(self,identities,history):
        self.identities=identities;self.history=history
        self.by_user={row['user_id']:row for row in identities};self.by_email={};self.changes={}
        for row in identities:self.by_email.setdefault(normalize(row.get('email')),set()).add(row['user_id'])
        for h in history:
            self.changes.setdefault(h['user_id'],[]).append(h)
            if h['field_name']=='email':
                for k in ('old_value','new_value'):self.by_email.setdefault(normalize(h[k]),set()).add(h['user_id'])

    def subject(self,row,cutoff):
        current=dict(row);aliases={normalize(row['user_id'])}
        changes=sorted(self.changes.get(row['user_id'],[]),key=lambda h:timestamp(h['event_time']))
        for h in reversed(changes):
            if timestamp(h['event_time'])>timestamp(cutoff): current[h['field_name']]=h['old_value']
        for field in ('email','phone','email_hash'):
            if current.get(field): aliases.add(normalize(current[field]))
        for h in changes:
            if timestamp(h['event_time'])<=timestamp(cutoff): aliases.update(normalize(h[k]) for k in ('old_value','new_value') if h.get(k))
        provenance={key:[] for key in aliases}
        for h in self.history:
            if timestamp(h['event_time'])<=timestamp(cutoff):
                for k in ('old_value','new_value'):
                    key=normalize(h.get(k))
                    if key in provenance:provenance[key].append(dict(user_id=h['user_id'],event_time=h['event_time'],role=k,audit_id=h.get('audit_id','')))
        return Subject(row['user_id'],aliases,current,provenance,cutoff)

    def explicit_owners(self,observation):
        return {normalize(v) for k,v in observation.fields.items() if k in {'user_id','owner_user_id','customer_reference','subject_reference','subject_ref','subject_key','owner_key','uploaded_by'} and normalize(v) not in {'','null','none','anonymous','anonymized'} and (k in {'user_id','owner_user_id'} or normalize(v) in {normalize(u) for u in self.by_user} or re.fullmatch(r'user_\d+',normalize(v)))}

    def belongs(self,observation,subject,cutoff):
        """Historical keys find stale copies; explicit ownership always constrains joins."""
        stable=self.explicit_owners(observation)
        if stable:return stable=={normalize(subject.user_id)}
        for key in observation.identity_keys.intersection(subject.aliases):
            transfers=[p for p in subject.alias_provenance.get(key,[]) if p['user_id']!=subject.user_id and p['role']=='new_value' and timestamp(p['event_time'])<=timestamp(observation.observed_at)]
            other_current=[r for r in self.identities if r['user_id']!=subject.user_id and key in {normalize(r.get(k)) for k in ('email','phone','email_hash')} and r.get('updated_at') and timestamp(r['updated_at'])<=min(timestamp(cutoff),timestamp(observation.observed_at))]
            if not transfers and not other_current:return True
        return False

    def resolve(self,email,cutoff):
        key=normalize(email);candidates=[s for uid in self.by_email.get(key,set()) if key in (s:=self.subject(self.by_user[uid],cutoff)).aliases]
        current=[s for s in candidates if normalize(s.current.get('email'))==key]
        if len(current)==1:return current[0]
        if len(candidates)==1:return candidates[0]
        raise UnresolvedAudit('identity',{'email':email,'candidate_count':len(candidates)})
