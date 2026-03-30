import React, { useState } from 'react';

const PricingConfigurator = () => {
  const [selectedProductType, setSelectedProductType] = useState('Standard');
  const [priceOptions, setPriceOptions] = useState({ basePrice: 100, discount: 0, tax: 5 });
  const [chartData, setChartData] = useState([]);

  // Function to update price options based on selected product type
  const handleProductTypeChange = (type) => {
    setSelectedProductType(type);
    if (type === 'Premium') {
      setPriceOptions({ basePrice: 200, discount: 10, tax: 8 });
      setChartData([150, 175]); // Example data
    } else if (type === 'Standard') {
      setPriceOptions({ basePrice: 100, discount: 0, tax: 5 });
      setChartData([100, 105]); // Example data
    }
  }

  return (
    <div className='pricing-configurator'>
      <h2>Select Product Type</h2>
      <button onClick={() => handleProductTypeChange('Standard')}>Standard</button>
      <button onClick={() => handleProductTypeChange('Premium')}>Premium</button>

      <h2>Price Options</h2>
      <div className='price-options'>
        Base Price: ${priceOptions.basePrice}
        Discount: -${priceOptions.discount}
        Tax: +${priceOptions.tax}%
      </div>

      <h2>Price Chart</h2>
      <svg width='400' height='300'>
        <line x1='50' y1='275' x2='350' y2='275' stroke='black' strokeWidth='2'/>
        <line x1='50' y1='250' x2='350' y2='250' stroke='black' strokeWidth='2'/>
        <line x1='50' y1='225' x2='350' y2='225' stroke='black' strokeWidth='2'/>

        {chartData.map((value, index) => (
          <circle key={index} cx={(index + 1) * 90 + 50} cy={300 - value * 5} r='10' fill='blue'/>
        ))}
      </svg>

    </div>
  );
};

export default PricingConfigurator;
