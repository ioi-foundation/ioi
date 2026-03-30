import React, { useState } from 'react';

const PricingConfigurator = () => {
  const [selectedProductType, setSelectedProductType] = useState('Basic');
  const [priceOptions, setPriceOptions] = useState({
    Basic: 10,
    Premium: 25,
    Enterprise: 50
  });
  const [discountRate, setDiscountRate] = useState(0);
  const [taxRate, setTaxRate] = useState(0);

  const handleProductTypeChange = (event) => {
    setSelectedProductType(event.target.value);
  }

  const applyDiscount = () => {
    setPriceOptions(prevPrices => ({
      ...prevPrices,
      [selectedProductType]: prevPrices[selectedProductType] * (1 - discountRate / 100)
    }));
  }

  const applyTax = () => {
    setPriceOptions(prevPrices => ({
      ...prevPrices,
      [selectedProductType]: prevPrices[selectedProductType] * (1 + taxRate / 100)
    }));
  }

  return (
    <div className='pricing-configurator'>
      <section className='control-panel'>
        <label>Product Type:</label>
        <select value={selectedProductType} onChange={handleProductTypeChange}>
          <option value='Basic'>Basic</option>
          <option value='Premium'>Premium</option>
          <option value='Enterprise'>Enterprise</option>
        </select>

        <label>Discount Rate:</label>
        <input type='number' min='0' max='100' value={discountRate} onChange={(event) => setDiscountRate(event.target.value)} />

        <label>Tax Rate:</label>
        <input type='number' min='0' max='100' value={taxRate} onChange={(event) => setTaxRate(event.target.value)} />

        <button onClick={applyDiscount}>Apply Discount</button>
        <button onClick={applyTax}>Apply Tax</button>
      </section>

      <main className='primary-visualization'>
        <h1>Price Summary</h1>
        {Object.entries(priceOptions).map(([type, price]) => (
          <div key={type} className='price-summary'>
            <span>{type}: ${price.toFixed(2)}</span>
          </div>
        ))}
      </main>

      <aside className='inspectable-detail'>
        <h1>Details</h1>
        <p>Selected Product Type: {selectedProductType}</p>
        <p>Discount Rate: {discountRate}%</p>
        <p>Tax Rate: {taxRate}%</p>
      </aside>
    </div>
  );
};

export default PricingConfigurator;