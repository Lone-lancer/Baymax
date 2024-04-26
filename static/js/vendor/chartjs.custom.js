$.exists = function(selector) {
    return ($(selector).length > 0);
  }

if ($.exists('#tf-chart1')) {
var ctx = document.getElementById("tf-chart1").getContext('2d');
var strokeColor1 = '#ff5a5a',
    strokeColor2 = '#556bcc',
    strokeColor3 = '#358da1',
    strokeColor4 = '#4a8cff',
    strokeColor5 = '#ffc82c';

var strokeLabel1 ='$200k Under',
    strokeLabel2 ='$200k-$300k',
    strokeLabel3 ='$300k-$400k',
    strokeLabel4 ='$500k-$600k',
    strokeLabel5 ='$600k Under';

var strokePercentage1 = 40,
    strokePercentage2 = 50,
    strokePercentage3 = 80,
    strokePercentage4 = 90,
    strokePercentage5 = 100;


  $('.tf-circle-stroke .tf-tf-circle-label').eq(0).html(strokeLabel1).siblings().css('background-color', strokeColor1);
  $('.tf-circle-stroke .tf-tf-circle-label').eq(1).html(strokeLabel2).siblings().css('background-color', strokeColor2);
  $('.tf-circle-stroke .tf-tf-circle-label').eq(2).html(strokeLabel3).siblings().css('background-color', strokeColor3);
  $('.tf-circle-stroke .tf-tf-circle-label').eq(3).html(strokeLabel4).siblings().css('background-color', strokeColor4);
  $('.tf-circle-stroke .tf-tf-circle-label').eq(4).html(strokeLabel5).siblings().css('background-color', strokeColor5);

var myChart = new Chart(ctx, {
  type: 'pie',
  data: {
    labels: [strokeLabel1, strokeLabel2, strokeLabel3, strokeLabel4, strokeLabel5],
    datasets: [{
      backgroundColor: [
        strokeColor1,
        strokeColor2,
        strokeColor3,
        strokeColor4,
        strokeColor5
      ],
      data: [
        strokePercentage1,
        strokePercentage2,
        strokePercentage3,
        strokePercentage4,
        strokePercentage5
      ],
      borderWidth: 3
    }]
  },
  options: {
      cutoutPercentage: 60,
      legend: {
        position: 'right',
        display: false
      },
      tooltips: {
          displayColors:false,
          mode: 'nearest',
          intersect: false,
          position: 'nearest',
          xPadding: 8,
          yPadding: 8,
          caretPadding: 8,
          backgroundColor: '#666666',
          cornerRadius: 2,
          titleFontSize: 13,
          titleFontStyle: 'normal',
          titleFontFamily: 'Roboto',
          bodyFontSize: 13,
          footerFontFamily: 'Roboto'
        },
  }
});
}



if ($.exists('#tf-chart2')) {
// chart2
var ctx = document.getElementById('tf-chart2').getContext('2d');
var myChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: ['Jan 18', 'Feb 18', 'March 18', 'April 18', 'May 18', 'Jun 18', 'July 18'],
    datasets: [{
      label: 'Views',
      data: [100, 50, 150, 100, 100, 150, 100],
      pointBorderWidth: 0,
      backgroundColor: [
          'rgba(85, 107, 204, 0.078)'
      ],
      borderColor: [
          '#556bcc'
      ],
      borderWidth: 2,
      lineTension: 0,


    }]

  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    legend: {
      position: 'bottom',
      display:false
    },
    tooltips: {
      displayColors:false,
      mode: 'nearest',
      intersect: false,
      position: 'nearest',
      xPadding: 8,
      yPadding: 8,
      caretPadding: 8,
      backgroundColor: '#666666',
      cornerRadius: 2,
      titleFontSize: 13,
      titleFontStyle: 'normal',
      titleFontFamily: 'Roboto',
      bodyFontSize: 13,
      footerFontFamily: 'Roboto'
    },
    scales: {
      yAxes: [{
        ticks: {
          fontSize: 14,
          fontColor: '#b5b5b5',
          fontFamily: 'Roboto',
          padding: 15,
          beginAtZero: true,
          autoSkip: false,
          maxTicksLimit: 4
        },
        gridLines: { color: '#d8d8d8' }
        }],
        xAxes: [{
            ticks: {
                fontSize: 14,
                fontColor: '#b5b5b5',
                fontFamily: 'Roboto',
                padding: 5,
                beginAtZero: true,
                autoSkip: false,
                maxTicksLimit: 4
            },
            gridLines: { color: '#d8d8d8' }
        }],

    }
   }
});
}

if ($.exists('#tf-chart3')) {
// chart3
var ctx = document.getElementById('tf-chart3').getContext('2d');
var myChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: ['Jan 18', 'Feb 18', 'March 18', 'April 18', 'May 18', 'Jun 18', 'July 18'],
    datasets: [{
      label: 'Views',
      data: [100, 50, 150, 100, 100, 150, 100],
      pointBorderWidth: 0,
      backgroundColor: [
          'rgba(79, 174, 54, 0.078)'
      ],
      borderColor: [
          'rgba(79, 174, 54, 1)'
      ],
      borderWidth: 2,
      lineTension: 0,


    }]

  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    legend: {
      position: 'bottom',
      display:false
    },
    tooltips: {
      displayColors:false,
      mode: 'nearest',
      intersect: false,
      position: 'nearest',
      xPadding: 8,
      yPadding: 8,
      caretPadding: 8,
      backgroundColor: '#666666',
      cornerRadius: 2,
      titleFontSize: 13,
      titleFontStyle: 'normal',
      titleFontFamily: 'Roboto',
      bodyFontSize: 13,
      footerFontFamily: 'Roboto'
    },
    scales: {
      yAxes: [{
        ticks: {
          fontSize: 14,
          fontColor: '#b5b5b5',
          fontFamily: 'Roboto',
          padding: 15,
          beginAtZero: true,
          autoSkip: false,
          maxTicksLimit: 4
        },
        gridLines: { color: '#d8d8d8' }
        }],
        xAxes: [{
            ticks: {
                fontSize: 14,
                fontColor: '#b5b5b5',
                fontFamily: 'Roboto',
                padding: 5,
                beginAtZero: true,
                autoSkip: false,
                maxTicksLimit: 4
            },
            gridLines: { color: '#d8d8d8' }
        }],

    }
   }
});
}
