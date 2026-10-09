# RLS scan 2026-10-06T19:15:35.622Z

Projects scanned: 45. Public tables with RLS off: 112. Of those, readable with the anon key right now: 52.

| project | ref | table | anon read (HTTP / rows) | anon write grant | sensitive columns |
|---|---|---|---|---|---|
| franklabs | oyjyffqjhnhiacpcymdp | action_cost_estimates | 206 / 12 | yes | - |
| franklabs | oyjyffqjhnhiacpcymdp | action_risk_classifications | 206 / 22 | yes | - |
| franklabs | oyjyffqjhnhiacpcymdp | assay_audit_results | 200 / 0 | yes | - |
| franklabs | oyjyffqjhnhiacpcymdp | assay_outreach | 200 / 0 | yes | email_to email_subject email_body gmail_message_id |
| franklabs | oyjyffqjhnhiacpcymdp | assay_prospects | 206 / 92 | yes | repo_name contact_email contact_github_username |
| franklabs | oyjyffqjhnhiacpcymdp | default_network_allowlist | 206 / 9 | yes | - |
| franklabs | oyjyffqjhnhiacpcymdp | monthly_spend_archive | 206 / 6 | yes | - |
| franklabs | oyjyffqjhnhiacpcymdp | outreach_drafts | 206 / 9 | yes | body |
| facegate | qglzivwbaflnbrlcuvyc | _migrations | 206 / 18 | yes | name |
| facegate | qglzivwbaflnbrlcuvyc | action_assertions | 206 / 7 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | audit_log | 206 / 1807 | yes | session_id ip_address |
| facegate | qglzivwbaflnbrlcuvyc | consent_records | 206 / 238 | yes | ip_address |
| facegate | qglzivwbaflnbrlcuvyc | deletion_audit_log | 206 / 7 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | face_enrollments | 206 / 172 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | face_templates | 200 / 0 | yes | template_version template |
| facegate | qglzivwbaflnbrlcuvyc | face_templates_512 | 200 / 0 | yes | template_version template |
| facegate | qglzivwbaflnbrlcuvyc | liveness_challenges | 206 / 21 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | oidc_clients | 200 / 0 | yes | client_secret_hash name |
| facegate | qglzivwbaflnbrlcuvyc | oidc_grants | 200 / 0 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | oidc_sessions | 200 / 0 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | oidc_signing_keys | 200 / 0 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | processed_webhook_events | 200 / 0 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | risk_policies | 200 / 0 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | sessions | 206 / 62 | yes | ip_address location access_token_hash refresh_token_hash liveness_session_id |
| facegate | qglzivwbaflnbrlcuvyc | tenant_transform_seeds | 200 / 0 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | tenants | 206 / 2 | yes | name api_key_live api_key_test |
| facegate | qglzivwbaflnbrlcuvyc | threat_entries | 200 / 0 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | usage_events | 206 / 293 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | usage_summaries | 206 / 10 | yes | - |
| facegate | qglzivwbaflnbrlcuvyc | users | 206 / 172 | yes | name email phone |
| facegate | qglzivwbaflnbrlcuvyc | verification_attempts | 206 / 597 | yes | session_id ip_address error_message |
| Agent Hub | zqxujnxmyfvnrjasjeye | affiliate_referrals_archive | 200 / 0 | yes | payment_count first_payment_at cancellation_reason |
| Agent Hub | zqxujnxmyfvnrjasjeye | affiliate_rewards_archive | 200 / 0 | yes | last_applied_invoice_id |
| Agent Hub | zqxujnxmyfvnrjasjeye | agent_handoff_protocols | 200 / 0 | yes | handoff_prompt_template |
| Agent Hub | zqxujnxmyfvnrjasjeye | agent_learning_feedback | 200 / 0 | yes | - |
| Agent Hub | zqxujnxmyfvnrjasjeye | bizbox_agent_instances | 200 / 0 | yes | template_id |
| Agent Hub | zqxujnxmyfvnrjasjeye | bizbox_orchestration_plans | 200 / 0 | yes | - |
| Agent Hub | zqxujnxmyfvnrjasjeye | bizbox_team_agents | 206 / 7 | yes | team_template_id agent_template_id |
| Agent Hub | zqxujnxmyfvnrjasjeye | bizbox_team_instances | 200 / 0 | yes | - |
| Agent Hub | zqxujnxmyfvnrjasjeye | dynamic_confidence_thresholds | 200 / 0 | yes | - |
| Agent Hub | zqxujnxmyfvnrjasjeye | knowledge_base | 200 / 0 | yes | content |
| Agent Hub | zqxujnxmyfvnrjasjeye | semantic_analysis_cache | 200 / 0 | yes | message_hash message_text |
| Agent Hub | zqxujnxmyfvnrjasjeye | user_interaction_patterns | 200 / 0 | yes | - |
| Agent Hub | zqxujnxmyfvnrjasjeye | user_oauth_credential_audit | 200 / 0 | yes | credential_id ip_address |
| MGO Support | euvfjkvsqpajvjnmmznc | service_status_updates | 200 / 0 | yes | message |
| MGO Support | euvfjkvsqpajvjnmmznc | transaction_anomaly_action_configs | 206 / 5 | yes | - |
| MGO Support | euvfjkvsqpajvjnmmznc | transaction_anomaly_events | 200 / 0 | yes | resolution_notes |
| MGO Support | euvfjkvsqpajvjnmmznc | webhook_events | 206 / 28928 | yes | - |
| e2e-test-app | eiqntvlwhfgvnqjdyuip | shipsafe_demo_customers | 206 / 3 | yes | name email note |
| Life OS | kkjjyigipbhfazsaihqf | stripe_events | 200 / 0 | yes | - |
| primer | wcodsaclbcwwbqgdrpsc | agreement | 200 / 1 | yes | - |
| primer | wcodsaclbcwwbqgdrpsc | agreement_comment | 206 / 2 | yes | body |
| primer | wcodsaclbcwwbqgdrpsc | agreement_section | 206 / 4 | yes | body |
| primer | wcodsaclbcwwbqgdrpsc | agreement_term | 206 / 9 | yes | - |
| primer | wcodsaclbcwwbqgdrpsc | agreement_term_acceptance | 206 / 9 | yes | - |
| primer | wcodsaclbcwwbqgdrpsc | box_chat_message | 206 / 26 | yes | content |
| primer | wcodsaclbcwwbqgdrpsc | box_document | 206 / 16 | yes | filename |
| primer | wcodsaclbcwwbqgdrpsc | box_document_chunk | 206 / 26 | yes | content content_tsv |
| primer | wcodsaclbcwwbqgdrpsc | box_grounding | 206 / 39 | yes | - |
| primer | wcodsaclbcwwbqgdrpsc | box_instance | 200 / 1 | yes | - |
| primer | wcodsaclbcwwbqgdrpsc | box_member | 206 / 21 | yes | - |
| primer | wcodsaclbcwwbqgdrpsc | build_proposal | 206 / 2 | yes | content share_token platform_slug |
| feedback-hub | xbprebqvcgehtmrsvqep | _demo_event_reservations | 206 / 6 | yes | - |
| feedback-hub | xbprebqvcgehtmrsvqep | _demo_events | 206 / 12 | yes | name |
| feedback-hub | xbprebqvcgehtmrsvqep | _demo_reservation_edits | 206 / 2 | yes | notes |
| feedback-hub | xbprebqvcgehtmrsvqep | _demo_reservations | 200 / 1 | yes | family_name |
| feedback-hub | xbprebqvcgehtmrsvqep | _demo_seat_assignments | 206 / 24 | yes | - |
| feedback-hub | xbprebqvcgehtmrsvqep | claude_sessions | 206 / 3 | yes | claude_session_id |
| feedback-hub | xbprebqvcgehtmrsvqep | specialists | 200 / 1 | yes | name phone |
| feedback-hub | xbprebqvcgehtmrsvqep | test_runs | 206 / 5 | yes | - |
| feedback-hub | xbprebqvcgehtmrsvqep | test_steps | 206 / 38 | yes | request_latency_ms |
| propria-core | wjkfldyrifvvvtpxcjxp | agent_proposals | 206 / 684 | yes | - |
| propria-core | wjkfldyrifvvvtpxcjxp | hermes_voice_calls | 206 / 7 | yes | room_name phone_number |
| Secure Apps | kmjnujsqmijxdkbrwmql | sbom_generation_queue | 206 / 34 | yes | error_message |
| coral-harbour-pilot | oilrcfmjjdqkqdegqaqc | agent_proposals | 200 / 0 | yes | - |
| coral-harbour-pilot | oilrcfmjjdqkqdegqaqc | hermes_voice_calls | 200 / 0 | yes | room_name phone_number |
| coral-harbour-pilot | oilrcfmjjdqkqdegqaqc | pilot_email_replies | 206 / 13 | yes | body_hash |
| brazilnut-support | gtbhsoqljstkxokspaqn | service_status_updates | 200 / 0 | yes | message |
| brazilnut-support | gtbhsoqljstkxokspaqn | transaction_anomaly_action_configs | 206 / 5 | yes | - |
| brazilnut-support | gtbhsoqljstkxokspaqn | transaction_anomaly_events | 200 / 0 | yes | resolution_notes |
| brazilnut-support | gtbhsoqljstkxokspaqn | webhook_events | 200 / 0 | yes | - |
| seatrial-prod | zcxdjvwgpgotebehcfqv | cli_events | 206 / 98 | yes | os_platform repo_name session_id |
| LUCID | naznedwtakirzhkubtjb | cli_events | 206 / 92 | yes | os_platform repo_name session_id |
| mgo-asue | ghjclgcvcasmhtfdwbeu | forfeitures | 200 / 0 | yes | amount_cents |
| mgo-asue | ghjclgcvcasmhtfdwbeu | goal_contracts | 206 / 3 | yes | - |
| mgo-asue | ghjclgcvcasmhtfdwbeu | goal_fees | 200 / 1 | yes | amount_cents |
| mgo-asue | ghjclgcvcasmhtfdwbeu | goal_locks | 206 / 4 | yes | amount_cents |
| Fire-OS | ijqceszwouwiwxmpirqm | memory_audit_log | 206 / 5205 | yes | - |
| Grab & Go | mcijisnotideuvpzzqqe | geo_promotions | 200 / 0 | yes | promotion_name minimum_order_amount center_latitude |
| Grab & Go | mcijisnotideuvpzzqqe | legacy_user_migration | 206 / 7 | yes | phone email full_name encrypted_password |
| Grab & Go | mcijisnotideuvpzzqqe | order_abandonments | 200 / 0 | yes | session_id session_data |
| Grab & Go | mcijisnotideuvpzzqqe | order_favorites | 200 / 0 | yes | nickname total_amount |
| Grab & Go | mcijisnotideuvpzzqqe | order_modification_requests | 200 / 1 | yes | customer_message restaurant_response_message price_difference |
| Grab & Go | mcijisnotideuvpzzqqe | order_preparation_metrics | 200 / 0 | yes | - |
| Grab & Go | mcijisnotideuvpzzqqe | performance_logs_2025_08 | 200 / 0 | yes | message |
| Grab & Go | mcijisnotideuvpzzqqe | pickup_confirmations | 200 / 0 | yes | notes |
| Grab & Go | mcijisnotideuvpzzqqe | pickup_id_registry | 206 / 8 | yes | - |
| Grab & Go | mcijisnotideuvpzzqqe | pickup_transactions | 200 / 0 | yes | staff_notes |
| Grab & Go | mcijisnotideuvpzzqqe | pin_auth_sessions | 206 / 83 | yes | session_token phone_number ip_address |
| Grab & Go | mcijisnotideuvpzzqqe | review_prompts | 200 / 0 | yes | - |
| Grab & Go | mcijisnotideuvpzzqqe | sms_rate_limits | 200 / 0 | yes | phone_number |
| Grab & Go | mcijisnotideuvpzzqqe | social_shares | 200 / 0 | yes | platform share_content |
| Grab & Go | mcijisnotideuvpzzqqe | table_ordering_sessions | 200 / 0 | yes | session_token |
| Grab & Go | mcijisnotideuvpzzqqe | table_qr_codes | 200 / 0 | yes | max_concurrent_sessions current_sessions |
| Grab & Go | mcijisnotideuvpzzqqe | walk_in_queues | 200 / 0 | yes | customer_name customer_phone |
| GTS Statements | iscllkdaqrvwmjcfhqsh | statement_sends | 0 / - | yes | customer_name email_to included_invoices invoice_count error_message token_id |
| GTS Statements | iscllkdaqrvwmjcfhqsh | statement_tokens | 206 / 867 | yes | token customer_name customer_email |
| DMP Tech Support | iiniwmvcdfdgefyhgzte | knowledge_chunks | 206 / 722 | yes | content |
| DMP Tech Support | iiniwmvcdfdgefyhgzte | knowledge_docs | 206 / 230 | yes | content |
| IslandFlow | tyqxwawlgdhcpisyqyfd | spatial_ref_sys | 401 / - | yes | auth_name |
| MGO Management Dashboard | qfxgiyeufgjsovxupfej | spatial_ref_sys | 206 / 8500 | yes | auth_name |
| MGO Kiosk | qixunwahanapilwaaknn | voice_interaction_metrics | 401 / - | yes | - |
