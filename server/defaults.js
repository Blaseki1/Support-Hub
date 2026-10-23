const MODULES = [
  { id: 'search', name: 'Search Hub' }, { id: 'fees', name: 'Fees & Commissions' }, { id: 'txns', name: 'Transaction History' },
  { id: 'limits', name: 'Thresholds & Limits' }, { id: 'giftcards', name: 'Pending Giftcards' }, { id: 'gpl', name: 'GPL Token Checker' },
  { id: 'docs', name: 'Deleted Docs' },
];
const SPECIAL = ['dl_images', 'unmask'];
const ROLES = ['Admin', 'Supervisor', 'Agent'];
const exp = (m) => 'export:' + m;

function roleDefaults(role, customIds = []) {
  const ids = [...MODULES.map((m) => m.id), ...customIds];
  if (role === 'Admin') return [...ids, ...ids.map(exp), ...SPECIAL, 'admin'];
  if (role === 'Supervisor') return [...ids, ...ids.map(exp), 'unmask'];
  return ['search', 'txns', 'giftcards', ...customIds];
}

const BLANK = () => ({ base: '', datasource: '', slice: '', dashboard: '', rowLimit: 1000 });
const LOOKUP_COLS = ['USER_ID','PARTNER_ID','STATUS','Account_type','USER_NAME','MOBILE_NUMBER','FIRST_NAME','Name','EMAIL_ID','CREATED_DATE','CREATED_BY','LAST_MODIFIED_DATE','LAST_MODIFIED_BY'];
const SEARCH_COLS = ['USER_ID','PARTNER_ID','STATUS','Account_type','USER_NAME','MOBILE_NUMBER','FIRST_NAME','Middle_name','LAST_NAME','DOB','EMAIL_ID','CREATED_DATE','CREATED_BY','LAST_MODIFIED_DATE','LAST_MODIFIED_BY','IDENTIFICATION_TYPE','ID_NUMBER','PLACE_OF_ISSUE'];
const HIST_COLS = ['TRANSACTION_ID','TRANS_DATE','TRANS_TIME','TRANSACTION_DATE','STATUS_TYPE','SERVICE_NAME','WALLET_ID','WALLET_PARTNER_ID','WALLET_TYPE_ID','WALLET_SIDE','WALLET_NET_AMOUNT','TRANSACTION_AMOUNT','WALLET_BAL_BEFORE','WALLET_BAL_AFTER','OP_COMMISSION','OP_TXN_FEE','DP_TXN_FEE','OP_FEE','DP_FEE','OU_ID','OU_FULLNAME','OU_MSISDN','OP_ID','OP_PARENT_ID','OP_WALLET_ID','OP_MSISDN','OP_WALLET_ACTION','OP_FULL_NAME','DP_ID','DP_PARENT_ID','DP_WALLET_ID','DP_MSISDN','DP_WALLET_ACTION','DP_FULL_NAME','OTHER_USER_MSISDN','OTHER_USER_FULL_NAME','PARTNER_SERVICE_NAME','MASTER_TXN_ID','REMARKS','BILLER_SERVICE_NAME','ACCOUNT_DETAIL','ACCOUNT_DETAIL_2'];

const DOCS_COLS = ['partner_id','document_id','path','content_type'];
const GPL_COLS = ['TRANSACTION_ID','TRANSACTION_DATE','status','partner_msisdn','partner_name','biller_id','biller_name','biller_service_name','amount','Serial_number','UUID','LAST_MODIFIED_DATE','LAST_MODIFIED_BY'];
const FEES_COLS = ['service_name','SENDER_PROFILE','RECEIVER_PROFILE','start_val','end_val','start_range','end_range','fee_beneficiary','commission_beneficiary','fee_category','fee_type','fee_fixed_value','fee_fixed_value_display','fee_percentage_value','fee_percentage_display','commission_fixed_value','commission_fixed_value_display','commission_percentage_value','commission_percentage_display'];
const LIMITS_COLS = ['PROFILE_ID','PROFILE_NAME','LEVEL_ID','profile_type','profile_status','profile_soft_deleted','SERVICE_ID','service_display_name','SERVICE_NAME','service_status','IS_FINANCIAL','has_threshold','has_limit','min_send_amt','max_send_amt','max_receive_amt','daily_limit','weekly_limit','monthly_limit','DAILY_TXNS','WEEKLY_TXNS','MONTHLY_TXNS','min_wallet_balance','max_wallet_balance','low_balance_alert','REPORT_DOWNLOAD_SIZE','profile_last_modified'];
const defaultGpl = () => ({ env: 'uat', timeoutSec: 30, sampleUuid: '', envs: { uat: { base: 'https://gpl.utiliflex.dev', path: '/transactions/{uuid}/receipt' }, prod: { base: '', path: '/transactions/{uuid}/receipt' } } });

// UAT values come from the curls you shared. PROD is blank: fill it in under Data Sources when you go live.
const defaultConnections = () => ({
  'search.lookup': { module: 'search', label: 'Search Hub', desc: 'Finds accounts by ID card, username, MSISDN, name or email.', env: 'uat', timeoutSec: 60,
    envs: { uat: { base: 'http://superset.mmgtest.net:8091', datasource: 76, slice: 83, dashboard: 103, rowLimit: 1000 }, prod: BLANK() },
    endpoint: '/api/v1/chart/data', searchCols: ['ID_NUMBER','USER_NAME','MOBILE_NUMBER','FIRST_NAME','Middle_name','LAST_NAME','EMAIL_ID'],
    fixedFilters: [{ col: 'Account_type', op: 'IS NOT NULL' }], dateCol: '', orderBy: [], minChars: 3, columns: [...SEARCH_COLS] },
  'txns.lookup': { module: 'txns', label: 'Account lookup', desc: 'Finds accounts by username or mobile number.', env: 'uat', timeoutSec: 60,
    envs: { uat: { base: 'http://superset.mmgtest.net:8091', datasource: 74, slice: 76, dashboard: 99, rowLimit: 1000 }, prod: BLANK() },
    endpoint: '/api/v1/chart/data', searchCols: ['MOBILE_NUMBER','USER_NAME'], fixedFilters: [], dateCol: 'CREATED_DATE', orderBy: [], minChars: 4, columns: [...LOOKUP_COLS] },
  'gpl.lookup': { module: 'gpl', label: 'GPL token lookup', desc: 'Finds a GPL transaction by Transaction ID or UUID, and any other rows sharing that UUID.', env: 'uat', timeoutSec: 60,
    envs: { uat: { base: 'http://superset.mmgtest.net:8091', datasource: 70, slice: 71, dashboard: 94, rowLimit: 1000 }, prod: BLANK() },
    endpoint: '/api/v1/chart/data', searchCols: ['TRANSACTION_ID', 'UUID'], fixedFilters: [], dateCol: 'TRANSACTION_DATE', orderBy: [], minChars: 6, columns: [...GPL_COLS] },
  'docs.lookup': { module: 'docs', label: 'Partner documents', desc: 'Lists the stored document files (ID, selfie and so on) for a Partner ID. The files themselves come from S3.', env: 'uat', timeoutSec: 60,
    envs: { uat: { base: 'http://superset.mmgtest.net:8091', datasource: 79, slice: 86, dashboard: 107, rowLimit: 10000 }, prod: { ...BLANK(), rowLimit: 10000 } },
    endpoint: '/api/v1/chart/data', searchCols: ['partner_id'], fixedFilters: [], dateCol: '', orderBy: [['partner_id', false]], minChars: 1, columns: [...DOCS_COLS] },
  'fees.rules': { module: 'fees', label: 'Fees & Commissions', desc: 'Fee and commission rules by service, sender profile and receiver profile.', env: 'uat', timeoutSec: 60,
    envs: { uat: { base: 'http://superset.mmgtest.net:8091', datasource: 71, slice: 72, dashboard: 95, rowLimit: 5000 }, prod: { ...BLANK(), rowLimit: 5000 } },
    endpoint: '/api/v1/chart/data', searchCols: ['service_name', 'SENDER_PROFILE', 'RECEIVER_PROFILE'], fixedFilters: [], dateCol: '', orderBy: [], minChars: 1, columns: [...FEES_COLS] },
  'limits.rules': { module: 'limits', label: 'Thresholds & Limits', desc: 'Send and receive thresholds, limits and wallet capacity by profile and service.', env: 'uat', timeoutSec: 60,
    envs: { uat: { base: 'http://superset.mmgtest.net:8091', datasource: 77, slice: 84, dashboard: 104, rowLimit: 5000 }, prod: { ...BLANK(), rowLimit: 5000 } },
    endpoint: '/api/v1/chart/data', searchCols: ['PROFILE_NAME', 'service_display_name'], fixedFilters: [], dateCol: 'profile_last_modified', orderBy: [['PROFILE_NAME', true]], minChars: 1, columns: [...LIMITS_COLS] },
  'txns.history': { module: 'txns', label: 'Transaction history', desc: "Pulls one account's transactions using its Partner ID from the lookup.", env: 'uat', timeoutSec: 60,
    envs: { uat: { base: 'http://superset.mmgtest.net:8091', datasource: 73, slice: 79, dashboard: 101, rowLimit: 50000 }, prod: { ...BLANK(), rowLimit: 50000 } },
    endpoint: '/api/v1/chart/data', searchCols: ['WALLET_PARTNER_ID'], fixedFilters: [], dateCol: 'TRANS_DATE', orderBy: [['TRANSACTION_DATE', false]], minChars: 1, columns: [...HIST_COLS] },
});

module.exports = { defaultGpl, GPL_COLS, MODULES, SPECIAL, ROLES, exp, roleDefaults, defaultConnections, HIST_COLS, SEARCH_COLS, LOOKUP_COLS };
