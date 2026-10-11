from src.database import save_analysis, get_overview_stats, get_analysis_history

print('Before stats:', get_overview_stats())
new_id = save_analysis(
    analysis_type='phishing',
    input_summary='unit-test://example.com',
    predicted_class='Phishing',
    risk_level='High',
    probability=0.95,
    model_name='UnitTestModel',
    result_summary='Unit test insertion',
    details={'test': True}
)
print('Inserted id', new_id)
print('After stats:', get_overview_stats())
print('Last history record:', get_analysis_history(limit=1)[0])
