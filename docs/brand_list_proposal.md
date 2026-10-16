# Proposal: a larger brand list

`data/lists/brands.txt` has 6 brands today. More brands mean more look-alikes for training and a
wider rule check. **Nothing below has been added to the lists yet.**

Every domain in this table is **unverified**: it was written from memory, not checked. Before a row
goes into the lists, open the organisation's own official page (or an official government directory)
and confirm the exact domain. A wrong entry in the whitelist would always allow an attacker's
domain, so a row with any doubt stays out.

How to add a confirmed row: put the label in `brands.txt` and the domain in `whitelist.txt` in the
same change, then retrain (`python -m ml.train`).

Labels shorter than 6 letters only match as whole words (`snb-login.com`, not `snbx.com`). Very
common short words (`moi`, `moh`, `stc`) may still appear in innocent names; check the rule's false
positives in `python -m ml.evaluate` after adding them.

## Already in the list

| Label | Organisation | Candidate official domain | Status |
|---|---|---|---|
| absher | Absher (Ministry of Interior) | absher.sa | in whitelist, re-check before release |
| nafath | Nafath (national single sign-on) | nafath.sa | **unverified, missing from whitelist** |
| tawakkalna | Tawakkalna | ta.sdaia.gov.sa | **unverified, missing from whitelist** |
| alrajhi | Al Rajhi Bank | alrajhibank.com.sa | in whitelist, re-check before release |
| alinma | Alinma Bank | alinma.com | in whitelist, re-check before release |
| riyadbank | Riyad Bank | riyadbank.com | in whitelist, re-check before release |

## Proposed additions

| Label | Organisation | Candidate official domain | Status |
|---|---|---|---|
| snb, alahli | Saudi National Bank | alahli.com | unverified |
| sab, sabb | Saudi Awwal Bank | sab.com | unverified |
| alfransi | Banque Saudi Fransi | alfransi.com.sa | unverified |
| anb | Arab National Bank | anb.com.sa | unverified |
| bankaljazira | Bank AlJazira | bankaljazira.com | unverified |
| bankalbilad | Bank Albilad | bankalbilad.com | unverified |
| saib | Saudi Investment Bank | saib.com.sa | unverified |
| stcpay | stc pay | stcpay.com.sa | unverified |
| stc | stc | stc.com.sa | unverified |
| sadad | SADAD payments | sadad.com | unverified |
| mada | mada cards | mada.com.sa | unverified |
| splonline | Saudi Post (SPL) | splonline.com.sa | unverified |
| moi | Ministry of Interior | moi.gov.sa | unverified |
| moh | Ministry of Health | moh.gov.sa | unverified |
| najiz | Najiz (Ministry of Justice) | najiz.sa | unverified |
| qiwa | Qiwa | qiwa.sa | unverified |
| muqeem | Muqeem | muqeem.sa | unverified |
| ejar | Ejar | ejar.sa | unverified |
| nusuk | Nusuk | nusuk.sa | unverified |
| balady | Balady | balady.gov.sa | unverified |
| zatca | Zakat, Tax and Customs Authority | zatca.gov.sa | unverified |
| gosi | General Organization for Social Insurance | gosi.gov.sa | unverified |
| sama | Saudi Central Bank | sama.gov.sa | unverified |
| saudia | Saudia airline | saudia.com | unverified |
| aramco | Saudi Aramco | aramco.com | unverified |

Domains under `gov.sa` are a good sign but not proof: confirm the exact name, because a
look-alike such as `absher-gov.sa.example.com` also contains `gov.sa`.
