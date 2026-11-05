import $ from 'jquery';

// 活动页：把 URL 里的 msg 参数显示成欢迎语
const msg = new URLSearchParams(location.search).get('msg') || '欢迎';
$('#welcome').html('<p>' + msg + '</p>');
